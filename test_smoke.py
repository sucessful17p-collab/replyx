import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
from app.main import app


def test_health():
    client = TestClient(app)
    response = client.get('/health')
    assert response.status_code == 200
    assert response.json()['ok'] is True


def test_home_and_csrf_cookie():
    client = TestClient(app)
    response = client.get('/')
    assert response.status_code == 200
    assert 'RelayChat X' in response.text
    assert client.cookies.get('rc_csrf')


def test_openapi_contains_core_routes():
    client = TestClient(app)
    schema = client.get('/openapi.json').json()
    paths = schema['paths']
    assert '/api/register' in paths
    assert '/api/conversations/{cid}/messages' in paths
    assert '/api/pair/start' in paths
    assert '/api/passkeys/register/options' in paths


def test_pair_qr_and_scan_page():
    client = TestClient(app)
    home = client.get('/')
    csrf = client.cookies.get('rc_csrf')
    response = client.post('/api/pair/start', json={'device_name': 'Test browser'}, headers={'X-CSRF-Token': csrf})
    assert response.status_code == 200
    data = response.json()
    assert data['scan_url'].endswith('/pair/scan?token=' + data['token'])
    qr = client.get('/api/pair/qr/' + data['token'] + '.png')
    assert qr.status_code == 200
    assert qr.headers['content-type'] == 'image/png'
    scan = client.get('/pair/scan', params={'token': data['token']})
    assert scan.status_code == 200
    assert 'Sign in and continue' in scan.text


def test_pair_url_can_target_streamlit_portal(monkeypatch):
    from app import main
    monkeypatch.setattr(main, 'PAIR_BASE_URL', 'https://relaychat-portal.streamlit.app')
    monkeypatch.setattr(main, 'PAIR_SCAN_PATH', '')
    url = main.pair_scan_url('test_token-123')
    assert url == 'https://relaychat-portal.streamlit.app/?token=test_token-123'
