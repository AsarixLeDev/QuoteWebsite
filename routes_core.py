from __future__ import annotations

import hashlib
import io
import json
import shutil
import zipfile
from datetime import datetime
from typing import Dict, Any, Optional

from flask import (
    Blueprint, render_template, redirect, url_for, request, flash,
    send_file, abort, send_from_directory
)
from flask_login import current_user, login_user, logout_user, login_required

from auth import LoginUser
from paths import UPLOAD_DIR
from storage import (
    read_db, write_db, get_conf,
    check_admin_password, check_user_password,
    ensure_unique_usernames
)

import storage_sql as store

core_bp = Blueprint("core", __name__)

# en haut du fichier (imports)
from urllib.parse import urlsplit
import re
from flask import current_app

from storage import get_conf
limits = (get_conf(read_db()).get("limits") or {})
MAX_IMPORT_MB = int(limits.get("import_max_mb", 512))

def _is_safe_next(url: str | None) -> bool:
    if not url:
        return False
    parts = urlsplit(url)
    # uniquement chemin local (pas de schéma/host), et commence par /
    return parts.scheme == "" and parts.netloc == "" and url.startswith("/")


def _resolve_next_for_user(next_url: str | None, *, is_admin: bool, username: str) -> str:
    from storage import read_db
    from flask import url_for
    if not _is_safe_next(next_url):
        return url_for("core.dashboard")
    # /texts/<id>
    m = re.match(r"^/texts/(\d+)$", next_url or "")
    if m:
        text_id = int(m.group(1))
        db = read_db()
        t = next((x for x in db.get("texts", []) if int(x.get("id", -1)) == text_id), None)
        if not t:
            return url_for("core.dashboard")
        if is_admin or username in (t.get("allowed_usernames") or []):
            return next_url
        return url_for("core.dashboard")
    # /texts/<id>/edit → admin only
    m = re.match(r"^/texts/(\d+)/edit$", next_url or "")
    if m:
        return next_url if is_admin else url_for("core.dashboard")
    # par défaut, on accepte si c’est un chemin local
    return next_url


# ------------------- Helpers -------------------

def _safe_join(*parts: str) -> str:
    return "/".join(p.strip("/\\") for p in parts if p)


def _text_fingerprint(t: Dict[str, Any]) -> str:
    base = f"{t.get('title') or ''}\n{t.get('body') or ''}\n{t.get('date') or ''}\n{t.get('created_by') or ''}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


def _copy_into_zip(z: zipfile.ZipFile, src_path, arcname: str) -> bool:
    try:
        z.write(src_path, arcname=arcname)
        return True
    except FileNotFoundError:
        return False


def _load_backup_payload(file_storage) -> tuple[Dict[str, Any], Optional[zipfile.ZipFile]]:
    """Retourne (payload_json, zip_handle|None)."""
    filename = (file_storage.filename or "").lower()
    raw = file_storage.read()
    file_storage.seek(0)
    if filename.endswith(".zip"):
        zf = zipfile.ZipFile(io.BytesIO(raw))
        name = next((n for n in zf.namelist() if n.endswith("backup.json")), None)
        if not name:
            raise ValueError("Zip invalide: backup.json manquant.")
        payload = json.loads(zf.read(name).decode("utf-8"))
        return payload, zf
    else:
        payload = json.loads(raw.decode("utf-8"))
        return payload, None


def _import_assets_from_zip(zf: zipfile.ZipFile, arcpath: str) -> Optional[str]:
    """Extrait un fichier du zip sous /uploads. Retourne le nouveau nom ou None."""
    try:
        fname = arcpath.split("/")[-1]
        out = (UPLOAD_DIR / fname)
        if out.exists():
            stem = fname.rsplit(".", 1)[0]
            ext = "" if "." not in fname else "." + fname.rsplit(".", 1)[1]
            i = 1
            while (UPLOAD_DIR / f"{stem}_{i}{ext}").exists():
                i += 1
            out = UPLOAD_DIR / f"{stem}_{i}{ext}"
        with zf.open(arcpath) as src, open(out, "wb") as dst:
            shutil.copyfileobj(src, dst)
        return out.name
    except Exception:
        return None


AUDIO_EXTS = {"mp3", "m4a", "aac", "ogg", "wav", "webm", "opus"}


def _media_badge_for_text(t):
    url = (t.get("music_url") or t.get("music_original_url") or "").lower()
    mode = (t.get("youtube_mode") or "").lower()

    if url.startswith("/uploads/"):
        return {"icon": "🎵", "label": "Audio local"}

    if any(url.endswith("." + ext) for ext in AUDIO_EXTS):
        return {"icon": "🎵", "label": "Audio direct"}

    if "open.spotify.com" in url:
        return {"icon": "🟢", "label": "Spotify"}
    if "youtube.com" in url or "youtu.be" in url:
        return {"icon": "▶️", "label": "YouTube audio" if mode == "audio" else "YouTube vidéo"}
    if "soundcloud.com" in url:
        return {"icon": "☁️", "label": "SoundCloud"}
    if "deezer.com" in url:
        return {"icon": "🔷", "label": "Deezer"}
    if "music.apple.com" in url or "embed.music.apple.com" in url:
        return {"icon": "🍎", "label": "Apple Music"}
    return None


# ------------------- Contexte templates -------------------

@core_bp.app_context_processor
def inject_globals():
    db = read_db()
    conf = get_conf(db)
    sp = conf.get("spotify", {}) or {}
    has_spotify = bool(sp.get("client_id") and sp.get("redirect_uri"))

    spotify_connected = False
    try:
        from storage import get_spotify_token_record
        if getattr(current_user, "is_authenticated", False):
            spotify_connected = bool(get_spotify_token_record(db, current_user.get_id()))
    except Exception:
        spotify_connected = False

    return {
        "now": datetime.utcnow,
        "site_name": conf.get("site_name", "Pastel Notes"),
        "has_spotify": has_spotify,
        "spotify_connected": spotify_connected
    }


# ------------------- Routes publiques / auth -------------------

@core_bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("core.dashboard"))
    return redirect(url_for("core.login"))


@core_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        next_qs = request.form.get("next") or request.args.get("next")
        db = read_db()

        # admin ?
        if store.check_admin_password(username, password):
            login_user(LoginUser(username, True))
            current_app.logger.info("Login admin OK: %s", username)
            target = _resolve_next_for_user(next_qs, is_admin=True, username=username)
            flash("Connecté (admin).")
            return redirect(target)

        # user normal
        elif store.check_user_password(username, password):
            login_user(LoginUser(username, False))
            current_app.logger.info("Login user OK: %s", username)
            target = _resolve_next_for_user(next_qs, is_admin=False, username=username)
            flash("Connecté.")
            return redirect(target)

        # échec
        current_app.logger.warning("Login FAIL for username=%s", username)
        flash("Identifiants incorrects.")
    return render_template("login.html")


@core_bp.route("/logout")
@login_required
def logout_view():
    logout_user()
    flash("Déconnecté.")
    return redirect(url_for("core.login"))


# ------------------- Dashboard -------------------

@core_bp.route("/dashboard")
@login_required
def dashboard():
    is_admin = getattr(current_user, "is_admin", False)
    texts = store.list_texts_for_user(current_user.get_id(), is_admin)
    return render_template("dashboard.html", texts=texts)


# ------------------- Uploads (images/audio) -------------------

@core_bp.route("/uploads/<path:filename>")
@login_required
def uploaded_file(filename: str):
    # contrôle minimal : seuls les utilisateurs connectés peuvent accéder aux fichiers
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=False)


# ------------------- Admin: Backup ZIP -------------------

@core_bp.route("/admin/backup")
@login_required
def admin_backup():
    if not getattr(current_user, "is_admin", False):
        abort(403)

    db = read_db()
    data = json.loads(json.dumps(db))  # deep copy pour annoter

    assets_root = "assets"

    # Parcours des textes: embarquer fichiers + conserver les URLs originales
    for t in data.get("texts", []):
        t.setdefault("backup_assets", {})

        mus_url = t.get("music_url")
        if mus_url and isinstance(mus_url, str) and mus_url.startswith("/uploads/"):
            fname = mus_url.split("/")[-1]
            arc = _safe_join(assets_root, "music", fname)
            t["backup_assets"]["music_file"] = arc
        if not t.get("music_original_url") and mus_url and not mus_url.startswith("/uploads/"):
            t["music_original_url"] = mus_url

        if t.get("image_filename"):
            img = t["image_filename"]
            arc = _safe_join(assets_root, "images", img)
            t["backup_assets"]["image_file"] = arc
        if t.get("image_url") and not t.get("image_original_url"):
            t["image_original_url"] = t["image_url"]

    # Construction du zip
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        # Ajouter les assets présents sur disque
        for t in db.get("texts", []):
            # musique
            mus_url = t.get("music_url")
            if mus_url and isinstance(mus_url, str) and mus_url.startswith("/uploads/"):
                fname = mus_url.split("/")[-1]
                _copy_into_zip(z, UPLOAD_DIR / fname, _safe_join(assets_root, "music", fname))
            # image
            if t.get("image_filename"):
                img = t["image_filename"]
                _copy_into_zip(z, UPLOAD_DIR / img, _safe_join(assets_root, "images", img))

        # ajouter le JSON annoté
        z.writestr("backup.json", json.dumps(data, ensure_ascii=False, indent=2))

    buf.seek(0)
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return send_file(
        buf,
        as_attachment=True,
        download_name=f"pastel_notes_backup_{stamp}.zip",
        mimetype="application/zip",
    )


# ------------------- Admin: Import (.json / .zip) -------------------

@core_bp.route("/admin/import", methods=["GET", "POST"])
@login_required
def admin_import():
    if not getattr(current_user, "is_admin", False):
        abort(403)

    if request.method == "POST":
        if request.content_length and request.content_length > MAX_IMPORT_MB * 1024 * 1024:
            flash(f"Fichier trop volumineux (> {MAX_IMPORT_MB} Mo).")
            return redirect(url_for('core.admin_import'))
        f = request.files.get("file")
        replace_all = (request.form.get("replace_all") == "1")
        if not f or not f.filename:
            flash("Choisissez un fichier .json ou .zip.")
            return redirect(url_for("core.admin_import"))

        try:
            payload, zf = _load_backup_payload(f)
        except Exception as e:
            flash(f"Import impossible: {e}")
            return redirect(url_for("core.admin_import"))

        db = read_db()

        # --- Config: on NE REMPLACE PAS secret_key ni admin
        incoming_conf = (payload.get("config") or {})
        db_conf = db.setdefault("config", {})
        if replace_all:
            for k, v in incoming_conf.items():
                if k in {"secret_key", "admin"}:
                    continue
                db_conf[k] = v if v is not None else db_conf.get(k)
        else:
            for k, v in incoming_conf.items():
                if k in {"secret_key", "admin"}:
                    continue
                if k not in db_conf:
                    db_conf[k] = v

        # --- Users
        incoming_users = payload.get("users") or []
        if replace_all:
            db["users"] = []
        existing = {(u.get("username", "").strip().lower()) for u in db.get("users", [])}
        for u in incoming_users:
            uname = (u.get("username") or "").strip()
            if not uname:
                continue
            if uname.lower() in existing:
                continue
            db.setdefault("users", []).append({
                "username": uname,
                "password_hash": u.get("password_hash"),
                "created_at": u.get("created_at") or datetime.utcnow().isoformat(),
            })
            existing.add(uname.lower())

        # --- Texts
        incoming_texts = payload.get("texts") or []
        if replace_all:
            db["texts"] = []

        have_fp = {_text_fingerprint(t) for t in db.get("texts", [])}
        for t in incoming_texts:
            ba = t.get("backup_assets") or {}

            # musique
            new_music_url = t.get("music_url")
            if zf and ba.get("music_file"):
                newname = _import_assets_from_zip(zf, ba["music_file"])
                if newname:
                    new_music_url = f"/uploads/{newname}"

            # image
            new_image_filename = t.get("image_filename")
            if zf and ba.get("image_file"):
                newimg = _import_assets_from_zip(zf, ba["image_file"])
                if newimg:
                    new_image_filename = newimg

            new_text = {
                "id": t.get("id"),
                "title": t.get("title"),
                "body": t.get("body"),
                "context": t.get("context"),
                "music_url": new_music_url,
                "music_original_url": t.get("music_original_url"),
                "youtube_mode": t.get("youtube_mode"),
                "image_filename": new_image_filename,
                "image_url": t.get("image_url"),
                "image_original_url": t.get("image_original_url"),
                "date": t.get("date") or datetime.utcnow().isoformat(),
                "created_at": t.get("created_at") or datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat(),
                "created_by": t.get("created_by"),
                "allowed_usernames": t.get("allowed_usernames") or [],
            }
            fp = _text_fingerprint(new_text)
            if (not replace_all) and fp in have_fp:
                continue
            if not replace_all:
                if any(int(x.get("id", -1)) == int(new_text.get("id", -1)) for x in db.get("texts", [])):
                    new_text.pop("id", None)
            db.setdefault("texts", []).append(new_text)
            have_fp.add(fp)

        # sanitation
        ensure_unique_usernames(db)

        # recalcul next_ids.text
        try:
            max_id = max(int(t.get("id", 0)) for t in db.get("texts", []) if t.get("id") is not None)
        except ValueError:
            max_id = 0
        db.setdefault("next_ids", {})["text"] = int(max_id) + 1

        texts = db.get("texts", [])
        used = set()
        for t in texts:
            try:
                used.add(int(t.get("id")))
            except Exception:
                pass
        nid = (max(used) + 1) if used else 1
        for t in texts:
            try:
                int(t.get("id"))
            except Exception:
                t["id"] = nid
                nid += 1
        db.setdefault("next_ids", {})["text"] = nid

        write_db(db)
        flash("Import terminé.")
        return redirect(url_for("core.dashboard"))

    return render_template("import.html")
