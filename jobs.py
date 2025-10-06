from __future__ import annotations
import os, re, time, threading, secrets, traceback
from queue import Queue
from typing import Dict, Any, Optional
import yt_dlp  # pip install yt-dlp

from paths import UPLOAD_DIR
import storage_sql as store
from storage import read_db, write_db

JOBS: Dict[str, Dict[str, Any]] = {}
_JLOCK = threading.Lock()
_Q: "Queue[Dict[str, Any]]" = Queue()
_WORKER_STARTED = False

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
def _fmt_eta(sec):
    if sec is None: return ""
    if sec < 0: sec = 0
    m, s = divmod(int(sec), 60); h, m = divmod(m, 60)
    return f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"
def _fmt_rate(bps):
    if not bps or bps <= 0: return ""
    u=["B/s","KiB/s","MiB/s","GiB/s","TiB/s"]; i=0; v=float(bps)
    while v>=1024 and i<len(u)-1: v/=1024.0; i+=1
    return f"{v:.1f} {u[i]}"
def _fmt_size(b):
    if not b or b<=0: return ""
    u=["B","KiB","MiB","GiB","TiB"]; i=0; v=float(b)
    while v>=1024 and i<len(u)-1: v/=1024.0; i+=1
    return f"{v:.1f} {u[i]}"

def _get(job_id):
    with _JLOCK: return JOBS.get(job_id)
def _set(job_id, **kw):
    with _JLOCK:
        if job_id in JOBS: JOBS[job_id].update(kw)

def get_job(job_id): return _get(job_id)
def cancel_job(job_id: str) -> bool:
    j=_get(job_id);
    if not j: return False
    _set(job_id, cancel=True); return True
def retry_job(job_id: str) -> Optional[str]:
    j=_get(job_id);
    return enqueue_yt_audio(j["text_id"], j["url"]) if j else None

def _progress_hook(job_id: str):
    def hook(d):
        j=_get(job_id)
        if not j: return
        if j.get("cancel"): raise Exception("cancelled-by-user")
        st=d.get("status")
        if st=="downloading":
            try:
                tot=d.get("total_bytes") or d.get("total_bytes_estimate")
                dl=d.get("downloaded_bytes")
                p=int((dl/tot)*100) if tot and dl else (j.get("progress") or 0)
            except Exception:
                pct=(d.get("_percent_str","").strip().rstrip("%") or "0")
                p=int(float(_ANSI_RE.sub("", pct)))
            eta=_fmt_eta(d.get("eta")); spd=_fmt_rate(d.get("speed"))
            cur=_fmt_size(d.get("downloaded_bytes"))
            tot2=_fmt_size(d.get("total_bytes") or d.get("total_bytes_estimate"))
            parts=[x for x in [f"ETA {eta}" if eta else "", spd, f"{cur} / {tot2}" if cur and tot2 else ""] if x]
            _set(job_id, state="running", progress=p, message=" • ".join(parts) or "téléchargement…")
        elif st=="finished":
            _set(job_id, state="running", progress=100, message="finalisation…")
    return hook

def _do_yt_audio(job: Dict[str, Any]):
    job_id = job["id"]; text_id = int(job["text_id"]); url = job["url"]
    token = secrets.token_urlsafe(16)
    out_tmpl = str(UPLOAD_DIR / (token + ".%(ext)s"))
    ydl_opts = {
        "format": "bestaudio[ext=m4a]/bestaudio/best",
        "outtmpl": out_tmpl, "noplaylist": True,
        "quiet": True, "no_warnings": True,
        "progress_hooks": [_progress_hook(job_id)],
    }
    try:
        _set(job_id, state="running", progress=0, message="préparation…")
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=True)
            file_path = ydl.prepare_filename(info)
        if not file_path or not os.path.exists(file_path):
            _set(job_id, state="error", message="fichier final introuvable"); return
        # annulation juste après DL
        if (_get(job_id) or {}).get("cancel"):
            _set(job_id, state="cancelled", message="annulé")
            try: os.remove(file_path)
            except Exception: pass
            return
        rel_name = os.path.basename(file_path)

        # MAJ SQL: music_url local + original
        store.update_text(text_id, {"music_url": f"/uploads/{rel_name}", "music_original_url": url}, allowed_usernames=None)

        # nettoie le mapping job->texte dans data.json (progress bar)
        try:
            db=read_db()
            yt=db.get("jobs",{}).get("yt",{})
            if yt and str(text_id) in yt: yt[str(text_id)]=""
            write_db(db)
        except Exception: pass

        _set(job_id, state="done", progress=100, message="terminé")
    except Exception as e:
        traceback.print_exc()
        _set(job_id, state="error", message=str(e) or "échec extraction")

def _worker_loop():
    while True:
        job=_Q.get()
        try:
            if job.get("type")=="yt-audio": _do_yt_audio(job)
        finally:
            _Q.task_done()

def init_app(app=None):
    global _WORKER_STARTED
    if _WORKER_STARTED: return
    _WORKER_STARTED=True
    threading.Thread(target=_worker_loop, daemon=True).start()

def enqueue_yt_audio(text_id: int, url: str) -> str:
    job_id = secrets.token_urlsafe(12)
    job = {"id":job_id,"type":"yt-audio","text_id":int(text_id),"url":url,
           "state":"queued","progress":0,"message":"","cancel":False,"created_at":time.time()}
    with _JLOCK: JOBS[job_id]=job
    _Q.put(job)
    return job_id
