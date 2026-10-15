"""Create a consistent SQLite backup using SQLite's online backup API."""
import os, sqlite3
from datetime import datetime
from pathlib import Path
root=Path(__file__).resolve().parents[1]
source=Path(os.getenv('DB_PATH',root/'data'/'relaychat.db'))
outdir=Path(os.getenv('BACKUP_DIR',root/'backups')); outdir.mkdir(parents=True,exist_ok=True)
if not source.exists(): raise SystemExit(f'Database not found: {source}')
target=outdir/f'relaychat-{datetime.now().strftime("%Y%m%d-%H%M%S")}.sqlite3'
with sqlite3.connect(source) as src, sqlite3.connect(target) as dst: src.backup(dst)
print(f'Backup created: {target} ({target.stat().st_size} bytes)')
