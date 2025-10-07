from __future__ import annotations
import os, re, time, threading, secrets, traceback
from queue import Queue
from typing import Dict, Any, Optional
from storage import read_db, get_conf
import yt_dlp

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


def _cookief():
    try:
        conf = get_conf(read_db())
        path = ((conf.get("yt") or {}).get("cookies_path")) or ""
        return path if (path and os.path.isfile(path)) else None
    except Exception:
        return None

# ... au-dessus : _cookief(), _progress_hook(), etc.

def _do_yt_audio(job: Dict[str, Any]):
    job_id  = job["id"]
    text_id = int(job["text_id"])
    url     = job["url"]

    token = secrets.token_urlsafe(16)
    out_tmpl = str(UPLOAD_DIR / (token + ".%(ext)s"))

    # premier essai : m4a si dispo, sinon bestaudio; client android (contourne parfois age-restrictions)
    ydl_opts = {
        "format": "bestaudio[ext=m4a]/bestaudio/best",
        "outtmpl": out_tmpl,
        "noplaylist": True,
        "quiet": True,
        "no_warnings": True,
        "extractor_args": {"youtube": {"player_client": ["android"]}},
        "progress_hooks": [_progress_hook(job_id)],
    }
    ck = _cookief()
    if ck:
        ydl_opts["cookies"] = ck

    def _run_with(opts):
        with yt_dlp.YoutubeDL(opts) as y:
            info = y.extract_info(url, download=True)
            return y.prepare_filename(info)

    try:
        _set(job_id, state="running", progress=0, message="préparation…")
        try:
            file_path = _run_with(ydl_opts)
        except yt_dlp.utils.DownloadError as e1:
            # fallback 1 : format plus générique, sans client android
            if "Requested format is not available" in str(e1):
                opts2 = dict(ydl_opts)
                opts2.pop("extractor_args", None)
                opts2["format"] = "bestaudio/best"
                file_path = _run_with(opts2)
            else:
                raise

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
        store.update_text(text_id, {
            "music_url": f"/uploads/{rel_name}",
            "music_original_url": url
        }, allowed_usernames=None)

        # nettoie le mapping job->texte dans data.json (pour la barre)
        try:
            db = read_db()
            yt = db.get("jobs", {}).get("yt", {})
            if yt and str(text_id) in yt:
                yt[str(text_id)] = ""
                write_db(db)
        except Exception:
            pass

        _set(job_id, state="done", progress=100, message="terminé")

    except yt_dlp.utils.DownloadError as e:
        msg = "YouTube : format audio indisponible."
        if "Sign in to confirm you’re not a bot" in str(e):
            msg = "YouTube : connexion requise (ajoute un cookies.txt dans config.yt.cookies_path)."
        _set(job_id, state="error", message=msg)
    except Exception as e:
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
