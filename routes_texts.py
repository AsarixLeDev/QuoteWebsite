from __future__ import annotations

import re
import secrets
import urllib.parse
from datetime import datetime

from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

import jobs
from paths import UPLOAD_DIR
from storage import (
    read_db, write_db, next_id, list_users,
    get_spotify_token_record, get_conf
)

ALLOWED_IMAGE_EXTS = {"png", "jpg", "jpeg", "webp", "gif"}
ALLOWED_AUDIO_EXTS = {"mp3", "ogg", "wav", "m4a", "aac"}

texts_bp = Blueprint("texts", __name__)

from storage import get_conf
limits = (get_conf(read_db()).get("limits") or {})
MAX_UPLOAD_MB = int(limits.get("upload_max_mb", 32))

# ---------- Helpers upload ----------
def _is_allowed(filename: str, allowed: set[str]) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed


def _clean_opt(v: str | None) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return None if s == "" or s.lower() == "none" else s


def _save_upload(fs, allowed: set[str]) -> str | None:
    if not fs or not getattr(fs, "filename", ""):
        return None
    fname = secure_filename(fs.filename)
    if not fname or not _is_allowed(fname, allowed):
        return None
    ext = fname.rsplit(".", 1)[1].lower()
    new_name = f"{secrets.token_urlsafe(16)}.{ext}"
    (UPLOAD_DIR / new_name).write_bytes(fs.read())
    return new_name


# ---------- Download audio distant (YouTube, lien direct, etc.) ----------
def _download_audio_from_url(url: str) -> str | None:
    """
    Télécharge un audio distant dans /uploads et renvoie le filename local, sinon None.
    - URL audio directe (.mp3/.m4a/...) : via requests
    - YouTube & co. : via yt-dlp (ffmpeg recommandé)
    """
    base = url.split("#", 1)[0].split("?", 1)[0]
    # Direct audio
    if "." in base:
        ext = base.rsplit(".", 1)[1].lower()
        if ext in ALLOWED_AUDIO_EXTS:
            try:
                import requests
                r = requests.get(url, timeout=20, stream=True)
                r.raise_for_status()
                fname = f"{secrets.token_urlsafe(16)}.{ext}"
                with open(UPLOAD_DIR / fname, "wb") as f:
                    for chunk in r.iter_content(8192):
                        if chunk:
                            f.write(chunk)
                return fname
            except Exception:
                pass
    # yt-dlp
    try:
        import yt_dlp  # type: ignore
    except Exception:
        return None

    out_name = f"{secrets.token_urlsafe(16)}.m4a"
    out_path = str(UPLOAD_DIR / out_name)
    ydl_opts = {
        "format": "bestaudio/best",
        "outtmpl": out_path,
        "noplaylist": True,
        "quiet": True,
        "no_warnings": True,
        "postprocessors": [
            {"key": "FFmpegExtractAudio", "preferredcodec": "m4a", "preferredquality": "5"}
        ],
    }
    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            ydl.download([url])
        return out_name
    except Exception:
        return None


# ---------- Music embed detection ----------
def _detect_embed(url: str | None) -> dict:
    """
    Reconnaît: audio_direct, spotify, youtube, soundcloud, deezer, applemusic, link
    Suivi des shortlinks Deezer (link.deezer.com/s/...) et support Spotify /intl-xx/.
    """
    if not url:
        return {"type": "none", "src": None}
    u = url.strip()

    # direct audio par extension
    base = u.split("#", 1)[0].split("?", 1)[0]
    if "." in base:
        ext = base.rsplit(".", 1)[1].lower()
        if ext in ALLOWED_AUDIO_EXTS:
            return {"type": "audio_direct", "src": u}

    # ---------------- Spotify (support /intl-xx/)
    # ex: https://open.spotify.com/intl-fr/track/ID
    m = re.search(r"open\.spotify\.com/(?:intl-[a-z]{2}/)?(track|playlist|album)/([A-Za-z0-9]+)", u)
    if m:
        kind, sid = m.groups()
        return {"type": "spotify", "kind": kind, "id": sid, "src": f"https://open.spotify.com/embed/{kind}/{sid}"}

    # ---------------- YouTube (watch, youtu.be, shorts)
    try:
        p = urllib.parse.urlparse(u if re.match(r"^https?://", u) else "https://" + u.lstrip("/"))
    except Exception:
        p = urllib.parse.urlparse(u)
    host = (p.netloc or "").lower()
    path = (p.path or "")

    if "youtu.be" in host:
        vid = path.strip("/").split("/")[0] or None
        if vid:
            return {"type": "youtube", "id": vid, "src": f"https://www.youtube.com/embed/{vid}"}
    if "youtube.com" in host:
        m = re.match(r"^/shorts/([A-Za-z0-9_-]{5,})", path)
        if m:
            vid = m.group(1)
            return {"type": "youtube", "id": vid, "src": f"https://www.youtube.com/embed/{vid}"}
        qs = urllib.parse.parse_qs(p.query or "")
        vid = qs.get("v", [None])[0]
        if vid:
            return {"type": "youtube", "id": vid, "src": f"https://www.youtube.com/embed/{vid}"}

    # ---------------- SoundCloud
    if "soundcloud.com" in u:
        enc = urllib.parse.quote(u, safe="")
        return {"type": "soundcloud", "src": f"https://w.soundcloud.com/player/?url={enc}"}

    # ---------------- Deezer
    # 1) Shortlink link.deezer.com → suivre la redirection
    if "link.deezer.com" in host:
        try:
            import requests
            r = requests.get(u, allow_redirects=True, timeout=8)
            if r.status_code in (200, 301, 302) and r.url:
                u = r.url
                p = urllib.parse.urlparse(u)
                host = (p.netloc or "").lower()
                path = (p.path or "")
        except Exception:
            pass
    # 2) URL canonique deezer.com/<kind>/<id>
    if "deezer.com" in host:
        m = re.search(r"deezer\.com/(?:[a-z]{2}/)?(track|album|playlist)/(\d+)", u)
        if m:
            kind, did = m.groups()
            params = "autoplay=false" + ("" if kind == "track" else "&tracklist=true")
            return {"type": "deezer", "kind": kind, "id": did, "src": f"https://widget.deezer.com/widget/auto/{kind}/{did}?{params}"}

    # ---------------- Apple Music
    if "music.apple.com" in host:
        em = u.replace("music.apple.com", "embed.music.apple.com", 1)
        return {"type": "applemusic", "src": em}

    # fallback
    return {"type": "link", "src": u}



def _is_youtube(url: str | None) -> bool:
    if not url:
        return False
    try:
        s = url.strip()
        if s.startswith("//"):
            s = "https:" + s
        if not re.match(r"^https?://", s):
            s = "https://" + s.lstrip("/")
        p = urllib.parse.urlparse(s)
        host = (p.netloc or "").lower()
        return ("youtube.com" in host) or ("youtu.be" in host)
    except Exception:
        return False


# ---------- Routes ----------
@texts_bp.route("/texts/<int:text_id>")
@login_required
def view_text(text_id: int):
    db = read_db()
    t = next((x for x in db.get("texts", []) if int(x["id"]) == text_id), None)
    if not t:
        from flask import abort
        abort(404)
    if not getattr(current_user, "is_admin", False):
        if current_user.get_id() not in t.get("allowed_usernames", []):
            from flask import abort
            abort(403)

    vm = dict(t, date_dt=datetime.fromisoformat(t["date"]))
    # Détecte sur music_url OU music_original_url (utile pour YouTube en mode audio)
    vm["embed"] = _detect_embed(t.get("music_url") or t.get("music_original_url"))

    # --- Spotify : si non connecté, fournir meta + alternatives
    if vm["embed"].get("type") == "spotify":
        from spotify_utils import fetch_track_meta, build_alt_links
        is_connected = bool(get_spotify_token_record(db, current_user.get_id()))
        vm["spotify_connected"] = is_connected
        if not is_connected and vm["embed"].get("kind") == "track":
            meta = fetch_track_meta(vm["embed"].get("id"))
            if meta:
                vm["spotify_meta"] = meta
                vm["alt_links"] = build_alt_links(meta["title"], meta["artists"])

    return render_template("text_view.html", text=vm)


@texts_bp.route("/texts/new", methods=["GET", "POST"])
@login_required
def new_text():
    if not getattr(current_user, "is_admin", False):
        from flask import abort
        abort(403)
    db = read_db()
    admin_name = (get_conf(db).get("admin", {}) or {}).get("username", "admin")
    usernames = [u["username"] for u in list_users(db) if u["username"].strip().lower() != admin_name.strip().lower()]
    if request.method == "POST":
        if request.content_length and request.content_length > MAX_UPLOAD_MB * 1024 * 1024:
            flash(f"Fichier trop volumineux (> {MAX_UPLOAD_MB} Mo).")
            return render_template("text_form.html",is_new=True,users = usernames,text =None)
        title = _clean_opt(request.form.get("title"))
        body = request.form.get("body")  # requis, pas de clean ici
        context_val = _clean_opt(request.form.get("context"))

        music_url = _clean_opt(request.form.get("music_url"))
        image_remote_url = _clean_opt(request.form.get("image_url"))
        youtube_audio = (request.form.get("youtube_audio") == "1")

        date_str = (request.form.get("date") or "").strip()
        allowed = request.form.getlist("allowed_users")

        if not body:
            flash("Le texte est requis.")
            return render_template("text_form.html", is_new=True, users=usernames, text=None)

        # Date
        dt = datetime.utcnow()
        if date_str:
            try:
                dt = datetime.strptime(date_str, "%Y-%m-%dT%H:%M")
            except ValueError:
                flash("Format de date invalide.")
                return render_template("text_form.html", is_new=True, users=usernames, text=None)

        # Image upload
        img_fs = request.files.get("image_file")
        img_name = _save_upload(img_fs, ALLOWED_IMAGE_EXTS) if img_fs and img_fs.filename else None

        # Musique : upload prioritaire
        mus_fs = request.files.get("music_file")
        music_original_url = None
        youtube_mode = None
        if mus_fs and mus_fs.filename:
            mus_name = _save_upload(mus_fs, ALLOWED_AUDIO_EXTS)
            music_url = f"/uploads/{mus_name}"
        elif music_url and _is_youtube(music_url) and youtube_audio:
            music_original_url = music_url
            youtube_mode = "audio"
            music_url = None  # sera rempli par le job
        elif music_url and _is_youtube(music_url):
            youtube_mode = "video"

        t = {
            "id": next_id(db, "text"),
            "title": title,
            "body": body,
            "context": context_val,
            "music_url": music_url,
            "music_original_url": music_original_url,
            "youtube_mode": youtube_mode,  # "audio"/"video"/None
            "image_filename": img_name,
            "image_url": image_remote_url,
            "image_original_url": image_remote_url if image_remote_url else None,
            "date": dt.isoformat(),
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "created_by": current_user.get_id(),
            "allowed_usernames": [u for u in allowed if
                                  u in usernames and u.strip().lower() != admin_name.strip().lower()],
        }
        if youtube_mode == "audio" and music_original_url:
            t["yt_job_id"] = jobs.enqueue_yt_audio(t["id"], music_original_url)
        db.setdefault("texts", []).append(t)
        write_db(db)
        flash("Texte créé.")
        return redirect(url_for("texts.view_text", text_id=t["id"]))

    return render_template("text_form.html", is_new=True, users=usernames, text=None)


@texts_bp.route("/texts/<int:text_id>/edit", methods=["GET", "POST"])
@login_required
def edit_text(text_id: int):
    if not getattr(current_user, "is_admin", False):
        from flask import abort
        abort(403)
    db = read_db()
    admin_name = (get_conf(db).get("admin", {}) or {}).get("username", "admin")
    t = next((x for x in db.get("texts", []) if int(x["id"]) == text_id), None)
    if not t:
        from flask import abort
        abort(404)

    usernames = [u["username"] for u in list_users(db) if u["username"].strip().lower() != admin_name.strip().lower()]

    if request.method == "POST":
        if request.content_length and request.content_length > MAX_UPLOAD_MB * 1024 * 1024:
            flash(f"Fichier trop volumineux (> {MAX_UPLOAD_MB} Mo).")
            return render_template("text_form.html",
                                   is_new=False,
            users = usernames,
            text=dict(t, date_dt=datetime.fromisoformat(t["date"])))
        title = _clean_opt(request.form.get("title"))
        body = request.form.get("body")
        context_val = _clean_opt(request.form.get("context"))

        music_url = _clean_opt(request.form.get("music_url"))
        image_remote_url = _clean_opt(request.form.get("image_url"))
        youtube_audio = (request.form.get("youtube_audio") == "1")

        date_str = (request.form.get("date") or "").strip()
        allowed = request.form.getlist("allowed_users")

        if not body:
            flash("Le texte est requis.")
            vm = dict(t, date_dt=datetime.fromisoformat(t["date"]))
            return render_template("text_form.html", is_new=False, users=usernames, text=vm)

        # Date
        if date_str:
            try:
                t["date"] = datetime.strptime(date_str, "%Y-%m-%dT%H:%M").isoformat()
            except ValueError:
                flash("Format de date invalide.")
        else:
            t["date"] = datetime.utcnow().isoformat()

        # Image upload
        img_fs = request.files.get("image_file")
        if img_fs and img_fs.filename:
            new_img = _save_upload(img_fs, ALLOWED_IMAGE_EXTS)
            if new_img:
                t["image_filename"] = new_img
                t["image_url"] = None  # upload > URL

        # Musique
        mus_fs = request.files.get("music_file")
        if mus_fs and mus_fs.filename:
            mname = _save_upload(mus_fs, ALLOWED_AUDIO_EXTS)
            t["music_url"] = f"/uploads/{mname}"
            t["music_original_url"] = None
            t["youtube_mode"] = None
        else:
            if music_url:
                t["music_url"] = music_url
                if music_url and _is_youtube(music_url) and youtube_audio:
                    t["music_original_url"] = music_url
                    t["music_url"] = None
                    t["youtube_mode"] = "audio"
                    t["yt_job_id"] = jobs.enqueue_yt_audio(t["id"], music_url)
                elif music_url and _is_youtube(music_url):
                    t["music_original_url"] = None
                    t["youtube_mode"] = "video"
                    t.pop("yt_job_id", None)
                else:
                    t["music_original_url"] = None
                    t["youtube_mode"] = None
                    t.pop("yt_job_id", None)

        t["title"] = title
        t["body"] = body
        t["context"] = context_val

        if not t.get("image_filename"):
            t["image_url"] = image_remote_url
            if image_remote_url and not t.get("image_original_url"):
                t["image_original_url"] = image_remote_url

        t["allowed_usernames"] = [u for u in allowed if
                                  u in usernames and u.strip().lower() != admin_name.strip().lower()]
        t["updated_at"] = datetime.utcnow().isoformat()

        write_db(db)
        flash("Texte mis à jour.")
        return redirect(url_for("texts.view_text", text_id=t["id"]))

    vm = dict(t, date_dt=datetime.fromisoformat(t["date"]))
    return render_template("text_form.html", is_new=False, users=usernames, text=vm)


@texts_bp.route("/jobs/<job_id>/status")
@login_required
def job_status(job_id: str):
    j = jobs.get_job(job_id)
    if not j: return jsonify({"state": "unknown"}), 404
    return jsonify({"id": j["id"], "state": j["state"], "progress": j["progress"], "message": j.get("message", "")})


@texts_bp.route("/jobs/<job_id>/cancel", methods=["POST"])
@login_required
def job_cancel(job_id: str):
    # admin only pour annuler
    if not getattr(current_user, "is_admin", False):
        return jsonify({"error": "forbidden"}), 403
    ok = jobs.cancel_job(job_id)
    return jsonify({"ok": bool(ok)}), (200 if ok else 404)


@texts_bp.route("/jobs/<job_id>/retry", methods=["POST"])
@login_required
def job_retry(job_id: str):
    # admin only pour relancer
    if not getattr(current_user, "is_admin", False):
        return jsonify({"error": "forbidden"}), 403
    new_id = jobs.retry_job(job_id)
    if not new_id:
        return jsonify({"error": "unknown"}), 404

    # Rattache le nouveau job au texte qui porte encore yt_job_id=job_id
    db = read_db()
    t = next((x for x in db.get("texts", []) if x.get("yt_job_id") == job_id), None)
    if t:
        t["yt_job_id"] = new_id
        write_db(db)
    return jsonify({"ok": True, "job_id": new_id})
