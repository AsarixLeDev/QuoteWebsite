from __future__ import annotations
import re
import secrets
import urllib.parse
from datetime import datetime

from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify, abort
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

import jobs
from paths import UPLOAD_DIR
from storage import (
    read_db, write_db, get_conf, get_spotify_token_record
)
import storage_sql as store  # ORM SQL
import crypto_server as cserv


ALLOWED_IMAGE_EXTS = {"png", "jpg", "jpeg", "webp", "gif"}
ALLOWED_AUDIO_EXTS = {"mp3", "ogg", "wav", "m4a", "aac"}

texts_bp = Blueprint("texts", __name__)

# Limite d'upload lue depuis la config JSON
_limits = (get_conf(read_db()).get("limits") or {})
MAX_UPLOAD_MB = int(_limits.get("upload_max_mb", 32))


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
    - YouTube & co. : via yt-dlp (sans post-traitement si possible)
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

    token = secrets.token_urlsafe(16)
    out_tmpl = str(UPLOAD_DIR / (token + ".%(ext)s"))
    ydl_opts = {
        "format": "bestaudio[ext=m4a]/bestaudio/best",
        "outtmpl": out_tmpl,
        "noplaylist": True,
        "quiet": True,
        "no_warnings": True,
    }
    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=True)
            file_path = ydl.prepare_filename(info)
        import os
        if not file_path or not os.path.exists(file_path):
            return None
        return os.path.basename(file_path)
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

    # Spotify (support /intl-xx/)
    m = re.search(r"open\.spotify\.com/(?:intl-[a-z]{2}/)?(track|playlist|album)/([A-Za-z0-9]+)", u)
    if m:
        kind, sid = m.groups()
        return {"type": "spotify", "kind": kind, "id": sid, "src": f"https://open.spotify.com/embed/{kind}/{sid}"}

    # YouTube (watch, youtu.be, shorts)
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

    # SoundCloud
    if "soundcloud.com" in u:
        enc = urllib.parse.quote(u, safe="")
        return {"type": "soundcloud", "src": f"https://w.soundcloud.com/player/?url={enc}"}

    # Deezer
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

    # Apple Music
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


# ---------- Mapping job YouTube dans JSON (pour l'UI) ----------
def _yt_map_set(text_id: int, job_id: str) -> None:
    db = read_db()
    j = db.setdefault("jobs", {}).setdefault("yt", {})
    j[str(text_id)] = job_id
    write_db(db)


def _yt_map_get(text_id: int) -> str | None:
    db = read_db()
    return (db.get("jobs", {}).get("yt", {}) or {}).get(str(text_id))


def _yt_map_find_text_id(job_id: str) -> int | None:
    db = read_db()
    m = db.get("jobs", {}).get("yt", {}) or {}
    for k, v in m.items():
        if v == job_id:
            try:
                return int(k)
            except Exception:
                return None
    return None


# ---------- Routes ----------
@texts_bp.route("/texts/<int:text_id>")
@login_required
def view_text(text_id: int):
    # Récupère depuis SQL
    t = store.get_text_dict(text_id)
    if not t:
        from flask import abort
        abort(404)

    # Permissions
    if not getattr(current_user, "is_admin", False):
        if current_user.get_id() not in (t.get("allowed_usernames") or []):
            from flask import abort
            abort(403)

    # VM
    vm = dict(t)
    vm["date_dt"] = datetime.fromisoformat(t["date"]) if t.get("date") else datetime.utcnow()

    # déchiffre pour l’affichage
    title = t.get("title");
    body = t.get("body");
    context = t.get("context")
    if t.get("ciphertext") and t.get("cipher_nonce"):
        try:
            clear = cserv.decrypt_text_payload(t["created_by"], t["ciphertext"], t["cipher_nonce"])
            title = clear.get("title") or title
            body = clear.get("body")
            context = clear.get("context")
        except Exception:
            title = title or "(indéchiffrable)";
            body = "(indéchiffrable)";
            context = None

    vm["title"] = title or "(sans titre)"
    vm["body"] = body
    vm["context"] = context

    # musique
    src = t.get("music_url") or t.get("music_original_url")
    vm["embed"] = _detect_embed(src)

    # état spotify (si tu l’utilises)
    try:
        vm["spotify_connected"] = bool(get_spotify_token_record(read_db(), current_user.get_id()))
    except Exception:
        vm["spotify_connected"] = False

    return render_template("text_view.html", text=vm)


@texts_bp.route("/texts/new", methods=["GET", "POST"])
@login_required
def new_text():

    # Liste des users (exclure l'admin du choix)
    admin_name = (get_conf(read_db()).get("admin", {}) or {}).get("username", "admin")
    usernames = [u["username"] for u in store.list_users() if u["username"].strip().lower() != admin_name.strip().lower()]

    if request.method == "POST":
        # limite métier
        if request.content_length and request.content_length > MAX_UPLOAD_MB * 1024 * 1024:
            flash(f"Fichier trop volumineux (> {MAX_UPLOAD_MB} Mo).")
            return render_template("text_form.html", is_new=True, users=usernames, text=None)

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

        # Musique
        mus_fs = request.files.get("music_file")
        music_original_url = None
        youtube_mode = None
        if mus_fs and mus_fs.filename:
            mus_name = _save_upload(mus_fs, ALLOWED_AUDIO_EXTS)
            music_url = f"/uploads/{mus_name}"
        elif music_url and _is_youtube(music_url) and youtube_audio:
            music_original_url = music_url
            youtube_mode = "audio"
            music_url = None  # sera rempli à la fin du job
        elif music_url and _is_youtube(music_url):
            youtube_mode = "video"

        allowed_final_list = [u for u in allowed if u in usernames and u.strip().lower() != admin_name.strip().lower()]

        clear = {"title": title, "body": body, "context": context_val}
        enc = cserv.encrypt_text_payload(current_user.get_id(), clear)

        text_id = store.create_text(
            current_user.get_id(),
            {
                "cipher_alg": enc["cipher_alg"],
                "ciphertext": enc["ciphertext"],
                "cipher_nonce": enc["cipher_nonce"],
                "default_allow": (request.form.get("default_allow") == "1"),
                "music_url": music_url,
                "music_original_url": music_original_url,
                "image_filename": img_name,
                "image_url": image_remote_url,
                "image_original_url": image_remote_url if image_remote_url else None,
                "date_dt": dt,
            },
            allowed_final_list,
        )

        if youtube_mode == "audio" and music_original_url:
            job_id = jobs.enqueue_yt_audio(text_id, music_original_url)
            _yt_map_set(text_id, job_id)

        flash("Texte créé.")
        return redirect(url_for("texts.view_text", text_id=text_id))

    return render_template("text_form.html", is_new=True, users=usernames, text=None)


@texts_bp.route("/texts/<int:text_id>/edit", methods=["GET", "POST"])
@login_required
def edit_text(text_id: int):
    if not getattr(current_user, "is_admin", False):
        from flask import abort
        abort(403)

    t = store.get_text_dict(text_id)
    if not t:
        from flask import abort
        abort(404)

    admin_name = (get_conf(read_db()).get("admin", {}) or {}).get("username", "admin")
    usernames = [u["username"] for u in store.list_users() if u["username"].strip().lower() != admin_name.strip().lower()]

    if request.method == "POST":
        if request.content_length and request.content_length > MAX_UPLOAD_MB * 1024 * 1024:
            flash(f"Fichier trop volumineux (> {MAX_UPLOAD_MB} Mo).")
            vm = dict(t, date_dt=datetime.fromisoformat(t["date"]))
            return render_template("text_form.html", is_new=False, users=usernames, text=vm)

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
        date_dt = None
        if date_str:
            try:
                date_dt = datetime.strptime(date_str, "%Y-%m-%dT%H:%M")
            except ValueError:
                flash("Format de date invalide.")

        # Image upload
        img_fs = request.files.get("image_file")
        new_img = None
        if img_fs and img_fs.filename:
            new_img = _save_upload(img_fs, ALLOWED_IMAGE_EXTS)

        # Musique
        mus_fs = request.files.get("music_file")
        data_update = {
            "title": title,
            "body": body,
            "context": context_val,
        }

        if date_dt:
            data_update["date_dt"] = date_dt

        if new_img:
            data_update["image_filename"] = new_img
            data_update["image_url"] = None
        else:
            if image_remote_url and not t.get("image_filename"):
                data_update["image_url"] = image_remote_url
                if not t.get("image_original_url"):
                    data_update["image_original_url"] = image_remote_url

        if mus_fs and mus_fs.filename:
            mname = _save_upload(mus_fs, ALLOWED_AUDIO_EXTS)
            data_update["music_url"] = f"/uploads/{mname}"
            data_update["music_original_url"] = None
            # stoppe un éventuel suivi de job
            _yt_map_set(text_id, "")  # vide le mapping
        else:
            if music_url:
                if _is_youtube(music_url) and youtube_audio:
                    data_update["music_original_url"] = music_url
                    data_update["music_url"] = None
                    job_id = jobs.enqueue_yt_audio(text_id, music_url)
                    _yt_map_set(text_id, job_id)
                elif _is_youtube(music_url):
                    data_update["music_url"] = music_url
                    data_update["music_original_url"] = None
                    _yt_map_set(text_id, "")  # plus de job
                else:
                    data_update["music_url"] = music_url
                    data_update["music_original_url"] = None
                    _yt_map_set(text_id, "")  # plus de job

        # Permissions
        allow_final = [u for u in allowed if u in usernames and u.strip().lower() != admin_name.strip().lower()]

        clear = {"title": title, "body": body, "context": context_val}
        enc = cserv.encrypt_text_payload(t["created_by"], clear)

        data_update.update({
            "cipher_alg": enc["cipher_alg"],
            "ciphertext": enc["ciphertext"],
            "cipher_nonce": enc["cipher_nonce"],
        })
        store.update_text(text_id, data_update, allow_final)

        # SQL update
        store.update_text(text_id, data_update, allow_final)

        flash("Texte mis à jour.")
        return redirect(url_for("texts.view_text", text_id=text_id))

    vm = dict(t, date_dt=datetime.fromisoformat(t["date"]))
    vm["yt_job_id"] = _yt_map_get(text_id)
    return render_template("text_form.html", is_new=False, users=usernames, text=vm)

@texts_bp.route("/texts/<int:text_id>/delete", methods=["POST"])
@login_required
def delete_text(text_id: int):
    # Récupérer le texte via la couche SQL
    t = store.get_text_dict(text_id)
    if not t:
        abort(404)

    # Droit : auteur ou admin
    if (not getattr(current_user, "is_admin", False)) and (t["created_by"] != current_user.get_id()):
        abort(403)

    # Suppression cascade (text_access, etc.)
    ok = store.delete_text(text_id)
    if ok:
        flash("Texte supprimé.")
    else:
        flash("Texte introuvable ou déjà supprimé.")

    return redirect(url_for("core.dashboard"))


# ---------- Jobs endpoints ----------
@texts_bp.route("/jobs/<job_id>/status")
@login_required
def job_status(job_id: str):
    j = jobs.get_job(job_id)
    if not j:
        return jsonify({"state": "unknown"}), 404
    return jsonify({
        "id": j["id"],
        "state": j["state"],
        "progress": j["progress"],
        "message": j.get("message", "")
    })


@texts_bp.route("/jobs/<job_id>/cancel", methods=["POST"])
@login_required
def job_cancel(job_id: str):
    if not getattr(current_user, "is_admin", False):
        return jsonify({"error": "forbidden"}), 403
    ok = jobs.cancel_job(job_id)
    return jsonify({"ok": bool(ok)}), (200 if ok else 404)


@texts_bp.route("/jobs/<job_id>/retry", methods=["POST"])
@login_required
def job_retry(job_id: str):
    if not getattr(current_user, "is_admin", False):
        return jsonify({"error": "forbidden"}), 403

    # Retrouve le text_id depuis le mapping JSON
    text_id = _yt_map_find_text_id(job_id)
    if not text_id:
        return jsonify({"error": "unknown_text"}), 404

    new_id = jobs.retry_job(job_id)
    if not new_id:
        return jsonify({"error": "unknown_job"}), 404

    # Met à jour le mapping
    _yt_map_set(text_id, new_id)
    return jsonify({"ok": True, "job_id": new_id})
