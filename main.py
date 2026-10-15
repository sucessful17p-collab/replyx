from __future__ import annotations
import os, re, json, time, hmac, hashlib, secrets, sqlite3, smtplib, mimetypes, urllib.parse, urllib.request
from email.message import EmailMessage
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
from contextlib import contextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import qrcode
from io import BytesIO

load_dotenv()
ROOT=Path(__file__).resolve().parent.parent
DATA=Path(os.getenv('DATA_DIR', ROOT/'data')); DATA.mkdir(parents=True,exist_ok=True)
UPLOADS=Path(os.getenv('UPLOAD_DIR', ROOT/'uploads')); UPLOADS.mkdir(parents=True,exist_ok=True)
DB_URL=os.getenv('DATABASE_URL','sqlite:///./data/relaychat.db')
DB_PATH=Path(DB_URL.removeprefix('sqlite:///')) if DB_URL.startswith('sqlite:///') else DATA/'relaychat.db'
if not DB_PATH.is_absolute(): DB_PATH=(ROOT/DB_PATH).resolve()
DB_PATH.parent.mkdir(parents=True,exist_ok=True)
SECRET=os.getenv('APP_SECRET','')
if len(SECRET)<32 or 'replace-with-a-long-random-secret' in SECRET:
    SECRET=secrets.token_urlsafe(48)
    print('[SECURITY] APP_SECRET is not configured; a temporary random secret was generated. Set APP_SECRET in .env for stable sessions.')
serializer=URLSafeTimedSerializer(SECRET, salt='relaychat-session')
BASE_URL=os.getenv('APP_BASE_URL','http://localhost:8001').rstrip('/')
# Use PAIR_BASE_URL for a phone-reachable address (LAN IP or HTTPS domain).
# Keep APP_BASE_URL on localhost when you want local WebAuthn/passkeys to work.
PAIR_BASE_URL=os.getenv('PAIR_BASE_URL','').strip().rstrip('/') or BASE_URL
# Default path serves the built-in scanner. Set PAIR_SCAN_PATH empty when the QR
# should open the companion Streamlit portal at its root URL.
PAIR_SCAN_PATH=os.getenv('PAIR_SCAN_PATH','/pair/scan').strip()
COOKIE_SECURE=os.getenv('COOKIE_SECURE','false').lower()=='true'
MAX_UPLOAD=int(os.getenv('MAX_UPLOAD_MB','12'))*1024*1024
app=FastAPI(title='RelayChat X API', version='1.0.0')
_rate_hits: dict[tuple[str,str], list[float]] = {}
app.mount('/static',StaticFiles(directory=ROOT/'app'/'static'),name='static')
templates=Jinja2Templates(directory=ROOT/'app'/'templates')

SCHEMA='''
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, phone TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, session_version INTEGER DEFAULT 0, email_verified INTEGER DEFAULT 0, phone_verified INTEGER DEFAULT 0, avatar TEXT DEFAULT '', bio TEXT DEFAULT '', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS codes(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,kind TEXT NOT NULL,code_hash TEXT NOT NULL,expires_at INTEGER NOT NULL,attempts INTEGER DEFAULT 0,UNIQUE(user_id,kind));
CREATE TABLE IF NOT EXISTS conversations(id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT DEFAULT '', is_group INTEGER DEFAULT 0, created_by INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS members(conversation_id INTEGER NOT NULL,user_id INTEGER NOT NULL,role TEXT DEFAULT 'member',joined_at TEXT NOT NULL,PRIMARY KEY(conversation_id,user_id));
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT,conversation_id INTEGER NOT NULL,sender_id INTEGER NOT NULL,body TEXT DEFAULT '',attachment_name TEXT DEFAULT '',attachment_path TEXT DEFAULT '',attachment_type TEXT DEFAULT '',created_at TEXT NOT NULL,edited_at TEXT DEFAULT '',deleted INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS receipts(message_id INTEGER NOT NULL,user_id INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'delivered',updated_at TEXT NOT NULL,PRIMARY KEY(message_id,user_id));
CREATE TABLE IF NOT EXISTS devices(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,device_name TEXT NOT NULL,token_hash TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL,last_seen TEXT NOT NULL,revoked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS pairings(id INTEGER PRIMARY KEY AUTOINCREMENT,token_hash TEXT NOT NULL UNIQUE,claim_hash TEXT NOT NULL DEFAULT '',owner_user_id INTEGER,device_name TEXT DEFAULT 'Web browser',status TEXT NOT NULL DEFAULT 'pending',expires_at INTEGER NOT NULL,created_at TEXT NOT NULL,device_id INTEGER);
CREATE TABLE IF NOT EXISTS passkeys(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,credential_id TEXT UNIQUE NOT NULL,public_key TEXT NOT NULL,sign_count INTEGER DEFAULT 0,transports TEXT DEFAULT '[]',created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,event TEXT NOT NULL,detail TEXT DEFAULT '',created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_messages_convo ON messages(conversation_id,id);
CREATE INDEX IF NOT EXISTS idx_members_user ON members(user_id,conversation_id);
'''
@contextmanager
def db():
    con=sqlite3.connect(DB_PATH,timeout=15); con.row_factory=sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON'); con.execute('PRAGMA journal_mode=WAL')
    try: yield con; con.commit()
    finally: con.close()
with db() as c: c.executescript(SCHEMA)

def now(): return datetime.now(timezone.utc).isoformat(timespec='seconds')
def password_hash(pw:str)->str:
    salt=secrets.token_bytes(16); out=hashlib.scrypt(pw.encode(),salt=salt,n=2**14,r=8,p=1)
    return 'scrypt$'+salt.hex()+'$'+out.hex()
def password_ok(pw, stored):
    try:
        _,s,h=stored.split('$'); got=hashlib.scrypt(pw.encode(),salt=bytes.fromhex(s),n=2**14,r=8,p=1)
        return hmac.compare_digest(got.hex(),h)
    except Exception: return False
def token_hash(s): return hashlib.sha256(s.encode()).hexdigest()
def pair_scan_url(token:str):
    path=PAIR_SCAN_PATH
    if path and not path.startswith('/'): path='/'+path
    query=urllib.parse.urlencode({'token':token})
    return f'{PAIR_BASE_URL}{path}?{query}' if path else f'{PAIR_BASE_URL}/?{query}'
def audit(uid,event,detail=''):
    with db() as c: c.execute('INSERT INTO audit(user_id,event,detail,created_at) VALUES(?,?,?,?)',(uid,event,detail[:250],now()))
def get_user(uid):
    if not uid: return None
    with db() as c: return c.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
def session_user(request):
    raw=request.cookies.get('rc_session')
    if not raw:return None
    try:
        data=serializer.loads(raw,max_age=60*60*24*14); uid=data.get('uid'); did=data.get('device_id'); user=get_user(uid)
        if not user or data.get('ver',0)!=user['session_version']: return None
        if did:
            with db() as c: device=c.execute('SELECT 1 FROM devices WHERE id=? AND user_id=? AND revoked=0',(did,uid)).fetchone()
            if not device: return None
        return user
    except Exception: return None
def set_session(resp,uid,device_id=None):
    user=get_user(uid); version=user['session_version'] if user else 0
    resp.set_cookie('rc_session',serializer.dumps({'uid':uid,'device_id':device_id,'ver':version,'nonce':secrets.token_hex(8)}),httponly=True,secure=COOKIE_SECURE,samesite='lax',max_age=1209600,path='/')
    resp.set_cookie('rc_csrf',secrets.token_urlsafe(24),httponly=False,secure=COOKIE_SECURE,samesite='lax',max_age=1209600,path='/')
def clear_session(resp):
    # Keep the CSRF cookie so the signed-out page can safely submit a new login/register request.
    resp.delete_cookie('rc_session',path='/')
def require_user(request):
    u=session_user(request)
    if not u: raise HTTPException(401,'Please sign in first')
    return u
def csrf(request):
    cookie=request.cookies.get('rc_csrf',''); header=request.headers.get('x-csrf-token','')
    if not cookie or not header or not hmac.compare_digest(cookie,header): raise HTTPException(403,'CSRF token missing or invalid; refresh and retry')
def public_user(u): return {'id':u['id'],'username':u['username'],'display_name':u['display_name'],'email':u['email'],'phone':u['phone'],'email_verified':bool(u['email_verified']),'phone_verified':bool(u['phone_verified']),'verified':bool(u['email_verified'] and u['phone_verified']),'avatar':u['avatar'],'bio':u['bio']}
def user_json(uid):
    u=get_user(uid); return public_user(u) if u else None

def send_email(to,subject,body):
    host=os.getenv('SMTP_HOST');
    if not host: print(f'[DEV EMAIL to={to}] {subject}: {body}'); return False
    msg=EmailMessage(); msg['Subject']=subject; msg['From']=os.getenv('SMTP_FROM','RelayChat X <noreply@example.com>'); msg['To']=to; msg.set_content(body)
    with smtplib.SMTP(host,int(os.getenv('SMTP_PORT','587')),timeout=15) as s:
        if os.getenv('SMTP_STARTTLS','true').lower()=='true': s.starttls()
        if os.getenv('SMTP_USER'): s.login(os.getenv('SMTP_USER'),os.getenv('SMTP_PASSWORD',''))
        s.send_message(msg)
    return True

def send_sms(phone,body):
    sid=os.getenv('TWILIO_ACCOUNT_SID'); auth=os.getenv('TWILIO_AUTH_TOKEN'); frm=os.getenv('TWILIO_FROM_NUMBER')
    if not (sid and auth and frm): print(f'[DEV SMS to={phone}] {body}'); return False
    url=f'https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json'
    payload=urllib.parse.urlencode({'To':phone,'From':frm,'Body':body}).encode()
    req=urllib.request.Request(url,data=payload,headers={'Authorization':'Basic '+__import__('base64').b64encode(f'{sid}:{auth}'.encode()).decode()})
    with urllib.request.urlopen(req,timeout=15) as r: return 200<=r.status<300

def make_code(uid,kind):
    code=f'{secrets.randbelow(1000000):06d}'; expires=int(time.time())+600
    with db() as c: c.execute('INSERT INTO codes(user_id,kind,code_hash,expires_at,attempts) VALUES(?,?,?,?,0) ON CONFLICT(user_id,kind) DO UPDATE SET code_hash=excluded.code_hash,expires_at=excluded.expires_at,attempts=0',(uid,kind,token_hash(code),expires))
    return code

def conversation_access(cid,uid):
    with db() as c: return c.execute('SELECT 1 FROM members WHERE conversation_id=? AND user_id=?',(cid,uid)).fetchone() is not None

def conversation_json(cid,uid):
    with db() as c:
        conv=c.execute('SELECT * FROM conversations WHERE id=?',(cid,)).fetchone()
        if not conv:return None
        members=c.execute('SELECT u.id,u.username,u.display_name,u.avatar,u.email_verified,u.phone_verified FROM members m JOIN users u ON u.id=m.user_id WHERE m.conversation_id=?',(cid,)).fetchall()
        last=c.execute('SELECT m.*,u.display_name sender_name FROM messages m JOIN users u ON u.id=m.sender_id WHERE conversation_id=? AND deleted=0 ORDER BY id DESC LIMIT 1',(cid,)).fetchone()
        unread=c.execute("SELECT COUNT(*) n FROM messages m WHERE m.conversation_id=? AND m.sender_id<>? AND m.id NOT IN (SELECT message_id FROM receipts WHERE user_id=? AND status='read')",(cid,uid,uid)).fetchone()['n']
    other=next((m for m in members if m['id']!=uid),None)
    title=conv['title'] if conv['is_group'] else (other['display_name'] if other else 'Saved messages')
    return {'id':cid,'title':title,'avatar':(other['avatar'] if other else '') if not conv['is_group'] else '', 'is_group':bool(conv['is_group']),'members':[dict(m) for m in members],'last_message':dict(last) if last else None,'unread':unread,'created_at':conv['created_at']}

def list_conversations(uid):
    with db() as c: ids=[r['conversation_id'] for r in c.execute('SELECT conversation_id FROM members WHERE user_id=?',(uid,)).fetchall()]
    out=[conversation_json(cid,uid) for cid in ids]; return sorted([x for x in out if x],key=lambda x:x['last_message']['id'] if x['last_message'] else 0,reverse=True)

class Hub:
    def __init__(self): self.connections:dict[int,set[WebSocket]]={}
    async def connect(self,uid,ws): await ws.accept(); self.connections.setdefault(uid,set()).add(ws)
    def disconnect(self,uid,ws): self.connections.get(uid,set()).discard(ws)
    async def send_user(self,uid,data):
        for ws in list(self.connections.get(uid,set())):
            try: await ws.send_json(data)
            except Exception: self.disconnect(uid,ws)
    async def broadcast_conversation(self,cid,data):
        with db() as c: uids=[r['user_id'] for r in c.execute('SELECT user_id FROM members WHERE conversation_id=?',(cid,)).fetchall()]
        for uid in uids: await self.send_user(uid,data)
hub=Hub()

@app.get('/health')
def health(): return {'ok':True,'service':'relaychat-x','time':now()}
@app.get('/',response_class=HTMLResponse)
def index(request:Request):
    u=session_user(request); csrf_token=request.cookies.get('rc_csrf') or secrets.token_urlsafe(24)
    resp=templates.TemplateResponse(request,'index.html',{'user':public_user(u) if u else None,'csrf':csrf_token})
    if not request.cookies.get('rc_csrf'): resp.set_cookie('rc_csrf',csrf_token,httponly=False,secure=COOKIE_SECURE,samesite='lax',max_age=1209600,path='/')
    return resp
@app.get('/api/me')
def me(request:Request):
    u=session_user(request); return {'user':public_user(u) if u else None,'csrf':request.cookies.get('rc_csrf','')}
@app.post('/api/register')
def register(request:Request,payload:dict):
    csrf(request)
    username=re.sub(r'[^a-zA-Z0-9_.-]','',str(payload.get('username','')).strip())[:24].lower()
    name=str(payload.get('display_name','')).strip()[:60]; email=str(payload.get('email','')).strip().lower(); phone=str(payload.get('phone','')).strip(); pw=str(payload.get('password',''))
    if not re.fullmatch(r'[a-z0-9_.-]{3,24}',username): raise HTTPException(400,'Username must be 3–24 characters (letters, digits, . _ -)')
    if not name or '@' not in email or len(phone)<7 or len(pw)<10: raise HTTPException(400,'Enter a name, valid email, phone and password (at least 10 characters)')
    try:
        with db() as c:
            cur=c.execute('INSERT INTO users(username,display_name,email,phone,password_hash,created_at) VALUES(?,?,?,?,?,?)',(username,name,email,phone,password_hash(pw),now())); uid=cur.lastrowid
            cur=c.execute('INSERT INTO conversations(title,is_group,created_by,created_at) VALUES(?,?,?,?)',('Saved messages',0,uid,now())); c.execute('INSERT INTO members(conversation_id,user_id,role,joined_at) VALUES(?,?,?,?)',(cur.lastrowid,uid,'owner',now()))
    except sqlite3.IntegrityError: raise HTTPException(409,'Username, email or phone is already registered')
    emailcode=make_code(uid,'email'); phonecode=make_code(uid,'phone')
    try: send_email(email,'Verify your RelayChat X email',f'Your verification code is {emailcode}. It expires in 10 minutes.')
    except Exception as e: print('[SMTP ERROR]',e)
    try: send_sms(phone,f'RelayChat X verification code: {phonecode}. Expires in 10 minutes.')
    except Exception as e: print('[SMS ERROR]',e)
    audit(uid,'register'); resp=JSONResponse({'ok':True,'message':'Account created. Verify your email and phone to receive the verified badge. Demo codes appear in server logs if providers are not configured.'}); set_session(resp,uid); return resp
@app.post('/api/login')
def login(request:Request,payload:dict):
    csrf(request); ident=str(payload.get('identity','')).strip().lower(); pw=str(payload.get('password',''))
    with db() as c: u=c.execute('SELECT * FROM users WHERE username=? OR email=? OR phone=?',(ident,ident,ident)).fetchone()
    if not u or not password_ok(pw,u['password_hash']): raise HTTPException(401,'Invalid login details')
    audit(u['id'],'login'); resp=JSONResponse({'ok':True,'user':public_user(u)}); set_session(resp,u['id']); return resp
@app.post('/api/logout')
def logout(request:Request):
    csrf(request); resp=JSONResponse({'ok':True}); clear_session(resp); return resp
@app.post('/api/verify/send')
def verify_send(request:Request,payload:dict):
    csrf(request); u=require_user(request); kind=payload.get('kind')
    if kind not in ('email','phone'): raise HTTPException(400,'Unknown verification type')
    if u[kind+'_verified']: return {'ok':True,'message':'Already verified'}
    code=make_code(u['id'],kind)
    try:
        if kind=='email': send_email(u['email'],'Your RelayChat X verification code',f'Your code is {code}. It expires in 10 minutes.')
        else: send_sms(u['phone'],f'RelayChat X verification code: {code}. Expires in 10 minutes.')
    except Exception as e: print('[DELIVERY ERROR]',e); raise HTTPException(502,'Delivery provider failed; check configuration')
    return {'ok':True,'message':'Code sent. In local demo mode, check the server terminal.'}
@app.post('/api/verify')
def verify(request:Request,payload:dict):
    csrf(request); u=require_user(request); kind=payload.get('kind'); code=str(payload.get('code','')).strip()
    if kind not in ('email','phone') or not re.fullmatch(r'\d{6}',code): raise HTTPException(400,'Enter a six-digit code')
    with db() as c:
        row=c.execute('SELECT * FROM codes WHERE user_id=? AND kind=?',(u['id'],kind)).fetchone()
        if not row or row['expires_at']<int(time.time()) or row['attempts']>=5:
            raise HTTPException(400,'Code expired or attempt limit reached; request another code')
        if not hmac.compare_digest(row['code_hash'],token_hash(code)):
            c.execute('UPDATE codes SET attempts=attempts+1 WHERE id=?',(row['id'],)); c.commit(); raise HTTPException(400,'Incorrect verification code')
        c.execute(f'UPDATE users SET {kind}_verified=1 WHERE id=?',(u['id'],)); c.execute('DELETE FROM codes WHERE user_id=? AND kind=?',(u['id'],kind))
    audit(u['id'],'verify_'+kind); return {'ok':True,'user':user_json(u['id'])}
@app.post('/api/password/reset/request')
def password_reset_request(request:Request,payload:dict):
    csrf(request); ident=str(payload.get('identity','')).strip().lower()
    with db() as c: u=c.execute('SELECT * FROM users WHERE email=? OR username=?',(ident,ident)).fetchone()
    if u:
        code=make_code(u['id'],'password_reset')
        try: send_email(u['email'],'Reset your RelayChat X password',f'Your password reset code is {code}. It expires in 10 minutes.')
        except Exception as e: print('[RESET EMAIL ERROR]',e)
    return {'ok':True,'message':'If that account exists, a reset code has been sent to its registered email. In local demo mode, check the server terminal.'}
@app.post('/api/password/reset/complete')
def password_reset_complete(request:Request,payload:dict):
    csrf(request); ident=str(payload.get('identity','')).strip().lower(); code=str(payload.get('code','')).strip(); password=str(payload.get('new_password',''))
    if len(password)<10 or not re.fullmatch(r'\d{6}',code): raise HTTPException(400,'Enter a six-digit code and a password of at least 10 characters')
    with db() as c: u=c.execute('SELECT * FROM users WHERE email=? OR username=?',(ident,ident)).fetchone()
    if not u: raise HTTPException(400,'Invalid or expired reset code')
    with db() as c:
        row=c.execute("SELECT * FROM codes WHERE user_id=? AND kind='password_reset'",(u['id'],)).fetchone()
        if not row or row['expires_at']<int(time.time()) or row['attempts']>=5 or not hmac.compare_digest(row['code_hash'],token_hash(code)):
            if row: c.execute('UPDATE codes SET attempts=attempts+1 WHERE id=?',(row['id'],)); c.commit()
            raise HTTPException(400,'Invalid or expired reset code')
        c.execute('UPDATE users SET password_hash=?,session_version=session_version+1 WHERE id=?',(password_hash(password),u['id']))
        c.execute("DELETE FROM codes WHERE user_id=? AND kind='password_reset'",(u['id'],))
        c.execute('UPDATE devices SET revoked=1 WHERE user_id=?',(u['id'],))
    audit(u['id'],'password_reset'); return {'ok':True,'message':'Password reset. Sign in again on your devices.'}

@app.get('/api/contacts')
def contacts(request:Request,q:str=''):
    u=require_user(request); q=q.strip().lower()[:80]
    with db() as c:
        rows=c.execute("SELECT id,username,display_name,avatar,email_verified,phone_verified FROM users WHERE id<>? AND (lower(username) LIKE ? OR lower(display_name) LIKE ?) ORDER BY display_name LIMIT 50",(u['id'],f'%{q}%',f'%{q}%')).fetchall()
    return {'contacts':[dict(r,verified=bool(r['email_verified'] and r['phone_verified'])) for r in rows]}
@app.get('/api/conversations')
def conversations(request:Request): return {'conversations':list_conversations(require_user(request)['id'])}
@app.post('/api/conversations/direct')
def direct(request:Request,payload:dict):
    csrf(request); u=require_user(request); other=int(payload.get('user_id',0))
    if other==u['id'] or not get_user(other): raise HTTPException(400,'Choose a valid contact')
    with db() as c:
        row=c.execute("SELECT c.id FROM conversations c JOIN members a ON a.conversation_id=c.id AND a.user_id=? JOIN members b ON b.conversation_id=c.id AND b.user_id=? WHERE c.is_group=0 ORDER BY c.id LIMIT 1",(u['id'],other)).fetchone()
        if row: return conversation_json(row['id'],u['id'])
        cur=c.execute('INSERT INTO conversations(title,is_group,created_by,created_at) VALUES(?,?,?,?)',('',0,u['id'],now())); cid=cur.lastrowid
        c.executemany('INSERT INTO members(conversation_id,user_id,role,joined_at) VALUES(?,?,?,?)',[(cid,u['id'],'owner',now()),(cid,other,'member',now())])
    return conversation_json(cid,u['id'])
@app.post('/api/conversations/group')
def group(request:Request,payload:dict):
    csrf(request); u=require_user(request); title=str(payload.get('title','')).strip()[:80]; ids=payload.get('user_ids',[])
    if not title or not isinstance(ids,list): raise HTTPException(400,'Enter a group name and members')
    ids=list(dict.fromkeys([u['id']]+[int(x) for x in ids if str(x).isdigit()]))
    if len(ids)<3: raise HTTPException(400,'A group needs you and at least two other members')
    if len(ids)>50 or any(not get_user(x) for x in ids): raise HTTPException(400,'Invalid group members (maximum 50)')
    with db() as c:
        cur=c.execute('INSERT INTO conversations(title,is_group,created_by,created_at) VALUES(?,?,?,?)',(title,1,u['id'],now())); cid=cur.lastrowid
        c.executemany('INSERT INTO members(conversation_id,user_id,role,joined_at) VALUES(?,?,?,?)',[(cid,x,'owner' if x==u['id'] else 'member',now()) for x in ids])
    audit(u['id'],'group_created',str(cid)); return conversation_json(cid,u['id'])
@app.get('/api/conversations/{cid}/messages')
def messages(request:Request,cid:int,before:int=0,limit:int=60):
    u=require_user(request)
    if not conversation_access(cid,u['id']): raise HTTPException(403,'Not a member of this conversation')
    limit=max(1,min(limit,100))
    with db() as c:
        rows=c.execute('SELECT m.*,u.username sender_username,u.display_name sender_name,u.avatar sender_avatar FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.conversation_id=? AND m.deleted=0 AND (?=0 OR m.id<?) ORDER BY m.id DESC LIMIT ?',(cid,before,before,limit)).fetchall()
        ids=[r['id'] for r in rows]
        for mid in ids: c.execute("INSERT INTO receipts(message_id,user_id,status,updated_at) VALUES(?,?,?,?) ON CONFLICT(message_id,user_id) DO UPDATE SET status='read',updated_at=excluded.updated_at",(mid,u['id'],'read',now()))
    result=[]
    with db() as c:
        member_ids=[x['user_id'] for x in c.execute('SELECT user_id FROM members WHERE conversation_id=?',(cid,)).fetchall()]
        for r in reversed(rows):
            others=[x for x in member_ids if x!=r['sender_id']]
            statuses=[]
            if others:
                marks=','.join('?' for _ in others)
                statuses=[x['status'] for x in c.execute(f'SELECT status FROM receipts WHERE message_id=? AND user_id IN ({marks})',[r['id']]+others).fetchall()]
            status='read' if others and len(statuses)==len(others) and all(x=='read' for x in statuses) else ('delivered' if statuses else 'sent')
            result.append(dict(r,status=status,attachment_url=f"/api/files/{r['id']}" if r['attachment_path'] else None))
    return {'messages':result}
@app.post('/api/conversations/{cid}/messages')
async def send_message(request:Request,cid:int,payload:dict):
    csrf(request); u=require_user(request)
    if not conversation_access(cid,u['id']): raise HTTPException(403,'Not a member of this conversation')
    body=str(payload.get('body','')).strip()
    if not body or len(body)>5000: raise HTTPException(400,'Message must be 1–5000 characters')
    with db() as c:
        cur=c.execute('INSERT INTO messages(conversation_id,sender_id,body,created_at) VALUES(?,?,?,?)',(cid,u['id'],body,now())); mid=cur.lastrowid
        c.execute('INSERT INTO receipts(message_id,user_id,status,updated_at) VALUES(?,?,?,?)',(mid,u['id'],'read',now()))
        row=c.execute('SELECT m.*,u.username sender_username,u.display_name sender_name,u.avatar sender_avatar FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.id=?',(mid,)).fetchone()
    msg=dict(row,status='sent',attachment_url=None)
    await hub.broadcast_conversation(cid,{'type':'message','conversation_id':cid,'message':msg})
    return {'message':msg}
@app.post('/api/conversations/{cid}/upload')
async def upload(request:Request,cid:int,file:UploadFile=File(...)):
    csrf(request); u=require_user(request)
    if not conversation_access(cid,u['id']): raise HTTPException(403,'Not a member of this conversation')
    data=await file.read(MAX_UPLOAD+1)
    if not data or len(data)>MAX_UPLOAD: raise HTTPException(413,f'File must be smaller than {MAX_UPLOAD//1024//1024} MB')
    mime=file.content_type or 'application/octet-stream'
    allowed=('image/','application/pdf','text/plain','application/zip','application/vnd.openxmlformats-officedocument','application/msword','audio/','video/')
    if not (mime.startswith('image/') or mime.startswith('audio/') or mime.startswith('video/') or any(mime.startswith(x) for x in allowed[1:])): raise HTTPException(415,'This file type is not allowed')
    safe=re.sub(r'[^a-zA-Z0-9._-]','_',Path(file.filename or 'upload').name)[:120]
    name=secrets.token_hex(16)+'_'+safe; path=UPLOADS/name; path.write_bytes(data)
    with db() as c:
        cur=c.execute('INSERT INTO messages(conversation_id,sender_id,body,attachment_name,attachment_path,attachment_type,created_at) VALUES(?,?,?,?,?,?,?)',(cid,u['id'],'',safe,name,mime,now())); mid=cur.lastrowid
        c.execute('INSERT INTO receipts(message_id,user_id,status,updated_at) VALUES(?,?,?,?)',(mid,u['id'],'read',now()))
        row=c.execute('SELECT m.*,u.username sender_username,u.display_name sender_name,u.avatar sender_avatar FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.id=?',(mid,)).fetchone()
    msg=dict(row,status='sent',attachment_url=f'/api/files/{mid}'); await hub.broadcast_conversation(cid,{'type':'message','conversation_id':cid,'message':msg}); return {'message':msg}
@app.get('/api/files/{mid}')
def get_file(request:Request,mid:int):
    u=require_user(request)
    with db() as c: row=c.execute('SELECT * FROM messages WHERE id=?',(mid,)).fetchone()
    if not row or not row['attachment_path'] or not conversation_access(row['conversation_id'],u['id']): raise HTTPException(404,'File not found')
    path=UPLOADS/Path(row['attachment_path']).name
    if not path.exists(): raise HTTPException(404,'File not found')
    return FileResponse(path,media_type=row['attachment_type'] or 'application/octet-stream',filename=row['attachment_name'],headers={'X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'none'; sandbox"})
@app.get('/api/profile')
def profile(request:Request): return {'user':public_user(require_user(request))}
@app.patch('/api/profile')
def update_profile(request:Request,payload:dict):
    csrf(request); u=require_user(request); name=str(payload.get('display_name',u['display_name'])).strip()[:60]; bio=str(payload.get('bio',u['bio'])).strip()[:240]
    if not name: raise HTTPException(400,'Display name cannot be blank')
    with db() as c: c.execute('UPDATE users SET display_name=?,bio=? WHERE id=?',(name,bio,u['id']))
    audit(u['id'],'profile_updated'); return {'user':user_json(u['id'])}
@app.post('/api/profile/avatar')
async def upload_avatar(request:Request,file:UploadFile=File(...)):
    csrf(request); u=require_user(request); data=await file.read(4*1024*1024+1)
    if not data or len(data)>4*1024*1024: raise HTTPException(413,'Avatar must be smaller than 4 MB')
    try:
        from PIL import Image, ImageOps
        import io
        img=Image.open(io.BytesIO(data)); img=ImageOps.exif_transpose(img).convert('RGB'); img.thumbnail((512,512))
        name=f'avatar_{u["id"]}_{secrets.token_hex(8)}.jpg'; path=UPLOADS/name; img.save(path,format='JPEG',quality=88,optimize=True)
    except Exception: raise HTTPException(415,'Upload a valid image file (JPEG, PNG or WebP)')
    with db() as c: c.execute('UPDATE users SET avatar=? WHERE id=?',(name,u['id']))
    audit(u['id'],'avatar_updated'); return {'user':user_json(u['id'])}
@app.get('/api/avatar/{uid}')
def get_avatar(uid:int):
    u=get_user(uid)
    if not u or not u['avatar']: raise HTTPException(404,'Avatar not found')
    path=UPLOADS/Path(u['avatar']).name
    if not path.exists(): raise HTTPException(404,'Avatar not found')
    return FileResponse(path,media_type='image/jpeg',headers={'Cache-Control':'public, max-age=300','X-Content-Type-Options':'nosniff'})

@app.get('/api/devices')
def devices(request:Request):
    u=require_user(request)
    with db() as c: rows=c.execute('SELECT id,device_name,created_at,last_seen FROM devices WHERE user_id=? AND revoked=0 ORDER BY id DESC',(u['id'],)).fetchall()
    return {'devices':[dict(x) for x in rows]}
@app.delete('/api/devices/{did}')
def revoke_device(request:Request,did:int):
    csrf(request); u=require_user(request)
    with db() as c: cur=c.execute('UPDATE devices SET revoked=1 WHERE id=? AND user_id=? AND revoked=0',(did,u['id']))
    if not cur.rowcount: raise HTTPException(404,'Device not found')
    audit(u['id'],'device_revoked',str(did)); return {'ok':True}
@app.post('/api/pair/start')
def pair_start(request:Request,payload:dict):
    csrf(request); u=session_user(request); token=secrets.token_urlsafe(32); claim_secret=secrets.token_urlsafe(32); expires=int(time.time())+180; name=str(payload.get('device_name','Web browser'))[:100]
    with db() as c: cur=c.execute('INSERT INTO pairings(token_hash,claim_hash,owner_user_id,device_name,status,expires_at,created_at) VALUES(?,?,?,?,?,?,?)',(token_hash(token),token_hash(claim_secret),u['id'] if u else None,name,'pending',expires,now()))
    scan_url=pair_scan_url(token)
    return {'pair_id':cur.lastrowid,'token':token,'claim_secret':claim_secret,'expires_at':expires,'scan_url':scan_url,'qr_payload':json.dumps({'type':'relaychat-pair','url':scan_url,'token':token,'expires_at':expires})}
@app.get('/api/pair/{token}/status')
def pair_status(token:str):
    with db() as c: row=c.execute('SELECT * FROM pairings WHERE token_hash=?',(token_hash(token),)).fetchone()
    if not row: raise HTTPException(404,'Pairing expired or not found')
    if row['expires_at']<int(time.time()) and row['status']!='approved': return {'status':'expired'}
    return {'status':row['status'],'device_name':row['device_name'],'expires_at':row['expires_at']}
@app.get('/pair/scan',response_class=HTMLResponse)
def pair_scan(request:Request,token:str):
    with db() as c: row=c.execute('SELECT status,expires_at FROM pairings WHERE token_hash=?',(token_hash(token),)).fetchone()
    valid=bool(row and row['expires_at']>=int(time.time()) and row['status']=='pending')
    user=session_user(request)
    return templates.TemplateResponse(request,'pair_scan.html',{'token':token,'user':public_user(user) if user else None,'valid':valid})
@app.post('/api/pair/{token}/approve')
def pair_approve(request:Request,token:str,payload:dict):
    csrf(request); u=require_user(request)
    if not (u['email_verified'] and u['phone_verified']): raise HTTPException(403,'Verify both email and phone before linking devices')
    with db() as c: row=c.execute('SELECT * FROM pairings WHERE token_hash=?',(token_hash(token),)).fetchone()
    if not row or row['expires_at']<int(time.time()) or row['status']!='pending': raise HTTPException(400,'Pairing code expired or already used')
    if row['owner_user_id'] and row['owner_user_id']!=u['id']: raise HTTPException(403,'Pairing was started by a different account')
    device_secret=secrets.token_urlsafe(40)
    with db() as c:
        cur=c.execute('INSERT INTO devices(user_id,device_name,token_hash,created_at,last_seen) VALUES(?,?,?,?,?)',(u['id'],row['device_name'],token_hash(device_secret),now(),now())); did=cur.lastrowid
        c.execute("UPDATE pairings SET owner_user_id=?,status='approved',device_id=? WHERE id=?",(u['id'],did,row['id']))
    audit(u['id'],'device_linked',row['device_name']); return {'ok':True,'device_id':did,'message':'Device linked. Sign in on the paired browser to start a session.'}
@app.post('/api/pair/{token}/claim')
def pair_claim(request:Request,token:str,payload:dict):
    csrf(request); secret=str(payload.get('claim_secret',''))
    with db() as c: row=c.execute('SELECT * FROM pairings WHERE token_hash=?',(token_hash(token),)).fetchone()
    if not row or row['expires_at']<int(time.time()) or row['status']!='approved': raise HTTPException(400,'Pairing is not approved or has expired')
    if not secret or not hmac.compare_digest(row['claim_hash'],token_hash(secret)): raise HTTPException(403,'Invalid device claim proof')
    uid=row['owner_user_id']
    if not uid: raise HTTPException(400,'Pairing has no account attached')
    with db() as c: c.execute("UPDATE pairings SET status='claimed' WHERE id=?",(row['id'],))
    audit(uid,'device_session_claimed',row['device_name']); resp=JSONResponse({'ok':True,'user':user_json(uid)}); set_session(resp,uid,row['device_id']); return resp

@app.get('/api/pair/qr/{token}.png')
def pair_qr(token:str):
    with db() as c: row=c.execute('SELECT * FROM pairings WHERE token_hash=?',(token_hash(token),)).fetchone()
    if not row or row['expires_at']<int(time.time()): raise HTTPException(404,'Pairing expired')
    img=qrcode.make(pair_scan_url(token),box_size=8,border=4); buf=BytesIO(); img.save(buf,format='PNG'); return Response(buf.getvalue(),media_type='image/png',headers={'Cache-Control':'no-store, max-age=0'})
# WebAuthn/passkeys use browser/device biometrics. The server never receives biometric images/templates.
def b64u(data:bytes)->str:
    import base64
    return base64.urlsafe_b64encode(data).decode().rstrip('=')
def unb64u(data:str)->bytes:
    import base64
    return base64.urlsafe_b64decode(data+'='*((4-len(data)%4)%4))
@app.post('/api/passkeys/register/options')
def passkey_register_options(request:Request):
    csrf(request); u=require_user(request)
    try:
        from webauthn import generate_registration_options, options_to_json
        from webauthn.helpers.structs import AuthenticatorSelectionCriteria, ResidentKeyRequirement, UserVerificationRequirement
        opts=generate_registration_options(rp_id=os.getenv('WEBAUTHN_RP_ID','localhost'),rp_name=os.getenv('WEBAUTHN_RP_NAME','RelayChat X'),user_id=str(u['id']).encode(),user_name=u['username'],user_display_name=u['display_name'],authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.PREFERRED,user_verification=UserVerificationRequirement.REQUIRED))
        challenge=b64u(opts.challenge)
        with db() as c: c.execute('INSERT INTO codes(user_id,kind,code_hash,expires_at,attempts) VALUES(?,?,?,?,0) ON CONFLICT(user_id,kind) DO UPDATE SET code_hash=excluded.code_hash,expires_at=excluded.expires_at,attempts=0',(u['id'],'webauthn_reg',challenge,int(time.time())+300))
        return json.loads(options_to_json(opts))
    except ImportError: raise HTTPException(501,'Install webauthn dependency to enable passkeys')
@app.post('/api/passkeys/register/complete')
def passkey_register_complete(request:Request,payload:dict):
    csrf(request); u=require_user(request)
    try:
        from webauthn import verify_registration_response
        with db() as c: row=c.execute("SELECT * FROM codes WHERE user_id=? AND kind='webauthn_reg'",(u['id'],)).fetchone()
        if not row or row['expires_at']<int(time.time()): raise HTTPException(400,'Passkey challenge expired')
        verification=verify_registration_response(payload,expected_challenge=unb64u(row['code_hash']),expected_rp_id=os.getenv('WEBAUTHN_RP_ID','localhost'),expected_origin=BASE_URL,require_user_verification=True)
        cred=b64u(verification.credential_id); public=b64u(verification.credential_public_key); count=verification.sign_count
        with db() as c:
            c.execute('INSERT INTO passkeys(user_id,credential_id,public_key,sign_count,transports,created_at) VALUES(?,?,?,?,?,?)',(u['id'],cred,public,count,json.dumps(payload.get('response',{}).get('transports',[])),now()))
            c.execute("DELETE FROM codes WHERE user_id=? AND kind='webauthn_reg'",(u['id'],))
        audit(u['id'],'passkey_registered'); return {'ok':True,'message':'Passkey registered. Your device handles biometric verification.'}
    except HTTPException: raise
    except Exception as e: raise HTTPException(400,'Passkey registration could not be verified: '+str(e)[:180])
@app.post('/api/passkeys/auth/options')
def passkey_auth_options(request:Request,payload:dict):
    csrf(request); ident=str(payload.get('identity','')).strip().lower()
    with db() as c: u=c.execute('SELECT * FROM users WHERE username=? OR email=? OR phone=?',(ident,ident,ident)).fetchone()
    if not u: raise HTTPException(404,'Account not found')
    try:
        from webauthn import generate_authentication_options, options_to_json
        from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement
        with db() as c: creds=c.execute('SELECT credential_id FROM passkeys WHERE user_id=?',(u['id'],)).fetchall()
        if not creds: raise HTTPException(404,'No passkey registered for this account')
        descriptors=[PublicKeyCredentialDescriptor(id=unb64u(r['credential_id'])) for r in creds]
        opts=generate_authentication_options(rp_id=os.getenv('WEBAUTHN_RP_ID','localhost'),allow_credentials=descriptors,user_verification=UserVerificationRequirement.REQUIRED)
        with db() as c: c.execute('INSERT INTO codes(user_id,kind,code_hash,expires_at,attempts) VALUES(?,?,?,?,0) ON CONFLICT(user_id,kind) DO UPDATE SET code_hash=excluded.code_hash,expires_at=excluded.expires_at,attempts=0',(u['id'],'webauthn_auth',b64u(opts.challenge),int(time.time())+300))
        return json.loads(options_to_json(opts))
    except HTTPException: raise
    except Exception as e: raise HTTPException(400,'Could not start passkey login: '+str(e)[:160])
@app.post('/api/passkeys/auth/complete')
def passkey_auth_complete(request:Request,payload:dict):
    csrf(request); ident=str(payload.pop('identity','')).strip().lower()
    with db() as c: u=c.execute('SELECT * FROM users WHERE username=? OR email=? OR phone=?',(ident,ident,ident)).fetchone()
    if not u: raise HTTPException(401,'Passkey login failed')
    try:
        from webauthn import verify_authentication_response
        credential_id=payload.get('id') or payload.get('rawId')
        with db() as c:
            challenge=c.execute("SELECT * FROM codes WHERE user_id=? AND kind='webauthn_auth'",(u['id'],)).fetchone()
            cred=c.execute('SELECT * FROM passkeys WHERE user_id=? AND credential_id=?',(u['id'],credential_id)).fetchone()
        if not challenge or challenge['expires_at']<int(time.time()) or not cred: raise HTTPException(401,'Passkey challenge expired or credential unknown')
        verification=verify_authentication_response(payload,expected_challenge=unb64u(challenge['code_hash']),expected_rp_id=os.getenv('WEBAUTHN_RP_ID','localhost'),expected_origin=BASE_URL,credential_public_key=unb64u(cred['public_key']),credential_current_sign_count=cred['sign_count'],require_user_verification=True)
        with db() as c:
            c.execute('UPDATE passkeys SET sign_count=? WHERE id=?',(verification.new_sign_count,cred['id'])); c.execute("DELETE FROM codes WHERE user_id=? AND kind='webauthn_auth'",(u['id'],))
        audit(u['id'],'passkey_login'); resp=JSONResponse({'ok':True,'user':public_user(u)}); set_session(resp,u['id']); return resp
    except HTTPException: raise
    except Exception as e: raise HTTPException(401,'Passkey authentication failed: '+str(e)[:160])

@app.websocket('/ws')
async def websocket_endpoint(ws:WebSocket):
    raw=ws.cookies.get('rc_session')
    try:
        session_data=serializer.loads(raw,max_age=60*60*24*14) if raw else {}
        uid=session_data.get('uid'); did=session_data.get('device_id'); ws_user=get_user(uid)
        if not ws_user or session_data.get('ver',0)!=ws_user['session_version']: uid=None
        if uid and did:
            with db() as c: active=c.execute('SELECT 1 FROM devices WHERE id=? AND user_id=? AND revoked=0',(did,uid)).fetchone()
            if not active: uid=None
    except Exception: uid=None
    if not uid or not get_user(uid): await ws.close(code=4401); return
    await hub.connect(uid,ws)
    try:
        while True:
            data=await ws.receive_json()
            if data.get('type')=='ping': await ws.send_json({'type':'pong'})
            elif data.get('type')=='read':
                cid=int(data.get('conversation_id',0))
                if conversation_access(cid,uid):
                    with db() as c: c.execute("UPDATE receipts SET status='read',updated_at=? WHERE user_id=? AND message_id IN (SELECT id FROM messages WHERE conversation_id=?)",(now(),uid,cid))
                    await hub.broadcast_conversation(cid,{'type':'receipts','conversation_id':cid})
            elif data.get('type')=='call-signal':
                # Relay WebRTC signaling only between members of an existing direct conversation.
                try:
                    cid=int(data.get('conversation_id',0)); target=int(data.get('target_user_id',0))
                    signal_type=str(data.get('signal_type',''))
                    allowed={'invite','accept','decline','offer','answer','ice','end'}
                    if signal_type not in allowed or target==uid: continue
                    with db() as c:
                        conv=c.execute('SELECT is_group FROM conversations WHERE id=?',(cid,)).fetchone()
                        members=[r['user_id'] for r in c.execute('SELECT user_id FROM members WHERE conversation_id=?',(cid,)).fetchall()]
                    if not conv or conv['is_group'] or uid not in members or target not in members: continue
                    payload=data.get('payload')
                    if payload is not None and len(json.dumps(payload))>180000: continue
                    sender=get_user(uid)
                    await hub.send_user(target,{'type':'call-signal','conversation_id':cid,'from_user_id':uid,'from_name':sender['display_name'] if sender else 'Contact','signal_type':signal_type,'mode':'video' if data.get('mode')=='video' else 'audio','call_id':str(data.get('call_id',''))[:80],'payload':payload})
                except (ValueError,TypeError):
                    continue
    except WebSocketDisconnect: hub.disconnect(uid,ws)
    except Exception: hub.disconnect(uid,ws)

@app.middleware('http')
async def security_headers(request:Request,call_next):
    # Lightweight single-process rate limiting for auth/verification endpoints.
    path=request.url.path
    limits={'/api/register':5,'/api/login':8,'/api/verify/send':5,'/api/verify':10,'/api/password/reset/request':5,'/api/password/reset/complete':8}
    if path.startswith('/api/'):
        ip=request.client.host if request.client else 'unknown'; now_s=time.time()
        keys=[(ip,'*')]
        if request.method=='POST' and path in limits: keys.append((ip,path))
        for key in keys:
            hits=[t for t in _rate_hits.get(key,[]) if now_s-t<60]
            cap=180 if key[1]=='*' else limits[path]
            if len(hits)>=cap:
                return JSONResponse({'detail':'Too many requests. Please wait a minute and try again.'},status_code=429)
            hits.append(now_s); _rate_hits[key]=hits
    response=await call_next(request)
    response.headers.setdefault('X-Content-Type-Options','nosniff'); response.headers.setdefault('X-Frame-Options','DENY'); response.headers.setdefault('Referrer-Policy','strict-origin-when-cross-origin'); response.headers.setdefault('Permissions-Policy','camera=(self), microphone=(), geolocation=()')
    if request.url.path.startswith('/api/'): response.headers.setdefault('Cache-Control','no-store')
    return response
