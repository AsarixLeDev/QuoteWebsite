from __future__ import annotations

import os
import re
import secrets
import threading
import time
from queue import Queue
from typing import Dict, Any, Optional

from paths import UPLOAD_DIR
from storage import read_db, write_db

JOBS: Dict[str, Dict[str, Any]] = {}
_JLOCK = threading.Lock()
_Q: "Queue[Dict[str, Any]]" = Queue()
_WORKER_STARTED = False

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')


def _strip_ansi(s: str | None) -> str:
    if not s: return ""
    return _ANSI_RE.sub("", s)


def _fmt_eta(sec: int | None) -> str:
    if sec is None: return ""
    if sec < 0: sec = 0
    m, s = divmod(int(sec), 60)
    h, m = divmod(m, 60)
    return (f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}")


def _fmt_rate(bps: float | None) -> str:
    if not bps or bps <= 0: return ""
    units = ["B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"]
    i = 0
    v = float(bps)
    while v >= 1024 and i < len(units) - 1:
        v /= 1024.0;
        i += 1
    return f"{v:.1f} {units[i]}"


def _fmt_size(b: float | None) -> str:
    if not b or b <= 0: return ""
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    i = 0
    v = float(b)
    while v >= 1024 and i < len(units) - 1:
        v /= 1024.0;
        i += 1
    return f"{v:.1f} {units[i]}"


def _set(job_id: str, **kw):
    with _JLOCK:
        if job_id in JOBS:
            JOBS[job_id].update(kw)


def _get(job_id: str) -> Optional[Dict[str, Any]]:
    with _JLOCK:
        return JOBS.get(job_id)


def _progress_hook(job_id: str):
    def hook(d):
        j = _get(job_id)
        if not j:
            return
        # annulation à chaud
        if j.get("cancel"):
            raise Exception("cancelled-by-user")

        status = d.get("status")
        if status == "downloading":
            # Pourcentage : privilégie le calcul numérique quand possible
            try:
                tot = d.get("total_bytes") or d.get("total_bytes_estimate")
                dl = d.get("downloaded_bytes")
                if tot and dl:
                    p = int(max(0.0, min(100.0, (dl / tot) * 100.0)))
                else:
                    # fallback sur la chaîne pourcent si fournie
                    pct_str = _strip_ansi(d.get("_percent_str", "")).strip().rstrip("%")
                    p = int(float(pct_str)) if pct_str else (j.get("progress") or 0)
            except Exception:
                p = j.get("progress") or 0

            # Message lisible : ETA + vitesse + taille
            eta_txt = _fmt_eta(d.get("eta"))
            spd_txt = _fmt_rate(d.get("speed"))
            cur_txt = _fmt_size(d.get("downloaded_bytes"))
            tot_txt = _fmt_size(d.get("total_bytes") or d.get("total_bytes_estimate"))
            parts = []
            if eta_txt: parts.append(f"ETA {eta_txt}")
            if spd_txt: parts.append(spd_txt)
            if cur_txt and tot_txt: parts.append(f"{cur_txt} / {tot_txt}")
            msg = " • ".join(parts) if parts else "téléchargement…"

            _set(job_id, state="running", progress=p, message=msg)

        elif status == "finished":
            # Plus de post-traitement (on télécharge déjà l’audio final), mais on garde un message court.
            _set(job_id, state="running", progress=100, message="finalisation…")

    return hook


def _do_yt_audio(job: Dict[str, Any]):
    """Télécharge la meilleure piste audio (sans post-traitement) et met à jour le texte."""
    job_id = job["id"]
    text_id = int(job["text_id"])
    url = job["url"]

    try:
        import yt_dlp  # type: ignore
    except Exception:
        _set(job_id, state="error", message="yt-dlp non installé")
        return

    # On laisse yt-dlp choisir l’extension finale (m4a si possible).
    token = secrets.token_urlsafe(16)
    out_tmpl = str(UPLOAD_DIR / (token + ".%(ext)s"))

    ydl_opts = {
        # m4a en priorité, sinon meilleure piste audio dispo
        "format": "bestaudio[ext=m4a]/bestaudio/best",
        "outtmpl": out_tmpl,
        "noplaylist": True,
        "quiet": True,
        "no_warnings": True,
        "progress_hooks": [_progress_hook(job_id)],
        # ⚠️ aucun postprocessor → pas de ffmpeg, donc pas de “post-traitement” bloquant
    }

    try:
        _set(job_id, state="running", progress=0, message="préparation…")
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=True)  # télécharge
            file_path = ydl.prepare_filename(info)  # chemin final avec extension
        if not file_path or not os.path.exists(file_path):
            _set(job_id, state="error", message="fichier final introuvable")
            return

        # Annulation éventuelle juste après le téléchargement
        j = get_job(job_id)
        if j and j.get("cancel"):
            _set(job_id, state="cancelled", message="annulé")
            try:
                os.remove(file_path)
            except Exception:
                pass
            return

        rel_name = os.path.basename(file_path)

        # Mise à jour du texte dans le JSON
        db = read_db()
        t = next((x for x in db.get("texts", []) if int(x.get("id", -1)) == text_id), None)
        if not t:
            _set(job_id, state="error", message="Texte introuvable")
            return

        t["music_url"] = f"/uploads/{rel_name}"
        t["music_original_url"] = url
        t["youtube_mode"] = "audio"
        t.pop("yt_job_id", None)
        t["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        write_db(db)

        _set(job_id, state="done", progress=100, message="terminé")
    except Exception as e:
        _set(job_id, state="error", message=str(e) or "échec extraction")


def _worker_loop():
    while True:
        job = _Q.get()
        try:
            if job.get("type") == "yt-audio":
                _do_yt_audio(job)
        finally:
            _Q.task_done()


def init_app(app=None):
    global _WORKER_STARTED
    if _WORKER_STARTED:
        return
    _WORKER_STARTED = True
    t = threading.Thread(target=_worker_loop, daemon=True)
    t.start()


def enqueue_yt_audio(text_id: int, url: str) -> str:
    job_id = secrets.token_urlsafe(12)
    job = {"id": job_id, "type": "yt-audio", "text_id": int(text_id), "url": url,
           "state": "queued", "progress": 0, "message": "", "cancel": False}
    with _JLOCK:
        JOBS[job_id] = job
    _Q.put(job)
    return job_id


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    return _get(job_id)


def cancel_job(job_id: str) -> bool:
    j = _get(job_id)
    if not j:
        return False
    _set(job_id, cancel=True)
    return True


def retry_job(job_id: str) -> Optional[str]:
    j = _get(job_id)
    if not j:
        return None
    # refile un nouveau job avec mêmes paramètres
    new_id = enqueue_yt_audio(j["text_id"], j["url"])
    return new_id
