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
    send_file, abort, send_from_directory, current_app
)
from flask_login import current_user, login_user, logout_user, login_required

from auth import LoginUser
from paths import UPLOAD_DIR
from storage import (
    read_db, write_db, get_conf,
    check_admin_password, check_user_password,
    ensure_unique_usernames
)

import crypto_server as cserv  # <-- ajouter
import storage_sql as store    # si pas déjà importé

core_bp = Blueprint("core", __name__)

# en haut du fichier (imports)
from urllib.parse import urlsplit
import re

from storage import get_conf
limits = (get_conf(read_db()).get("limits") or {})
MAX_IMPORT_MB = int(limits.get("import_max_mb", 512))

import os, io, json, zipfile, hashlib, secrets
from datetime import datetime
from flask import abort, send_file, flash, redirect, url_for, request
from werkzeug.utils import secure_filename

import storage_sql as store
from storage import read_db, get_conf
from paths import UPLOAD_DIR

# ---------- small utils ----------

def _safe_join(root, *parts) -> str:
    p = "/".join(str(x).strip("/\\") for x in parts if x)
    return f"{root.rstrip('/')}/{p}" if p else root

def _copy_into_zip(z: zipfile.ZipFile, src_path: os.PathLike, arcname: str):
    try:
        with open(src_path, "rb") as f:
            z.writestr(arcname, f.read())
    except FileNotFoundError:
        pass

def _load_backup_payload(fs) -> tuple[dict, zipfile.ZipFile | None]:
    data = fs.read()
    bio = io.BytesIO(data)
    try:
        zf = zipfile.ZipFile(bio)
        with zf.open("backup.json") as jf:
            payload = json.load(jf)
        return payload, zf
    except zipfile.BadZipFile:
        payload = json.loads(data.decode("utf-8"))
        return payload, None

def _import_asset_from_zip(zf: zipfile.ZipFile, arc: str) -> str | None:
    """Copie un asset depuis le zip dans /uploads et retourne le nouveau nom de fichier."""
    try:
        info = zf.getinfo(arc)
    except KeyError:
        return None
    name = os.path.basename(info.filename)
    ext = os.path.splitext(name)[1].lower()
    if ext not in (".jpg",".jpeg",".png",".gif",".webp",".mp3",".m4a",".ogg",".opus",".wav",".mp4"):
        ext = ""
    new = f"{secrets.token_urlsafe(16)}{ext}"
    out = UPLOAD_DIR / new
    with zf.open(info) as src, open(out, "wb") as dst:
        dst.write(src.read())
    return new

def _text_fingerprint_dict(d: dict) -> str:
    """Empreinte stable d'un texte (pour fusion) : auteur|date|SHA1(core)."""
    base = f"{d.get('created_by','')}|{d.get('date','')}"
    core = d.get("ciphertext") or f"{d.get('title','')}|{d.get('body','')}"
    return hashlib.sha1((base + "|" + core).encode("utf-8", "ignore")).hexdigest()[:16]


def _getv(row, name, default=None):
    """Récupère une valeur depuis un dict OU un objet ORM."""
    if isinstance(row, dict):
        return row.get(name, default)
    return getattr(row, name, default)

def _row_to_vm(row):
    """Convertit un row (dict ou ORM) en VM minimale (sans décrypt)."""
    rid = _getv(row, "id")
    date_dt = _getv(row, "date_dt") or _getv(row, "date")
    if isinstance(date_dt, str):
        try:
            date_dt = datetime.fromisoformat(date_dt)
        except Exception:
            date_dt = datetime.utcnow()
    if not date_dt:
        date_dt = datetime.utcnow()

    return {
        "id": rid,
        "date_dt": date_dt,
        "created_by": _getv(row, "created_by"),
        "title": _getv(row, "title"),
        "body": _getv(row, "body"),
        "context": _getv(row, "context"),
        "image_filename": _getv(row, "image_filename"),
        "image_url": _getv(row, "image_url"),
        "music_url": _getv(row, "music_url"),
    }

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


# Indicateur "média extérieur" pour le dashboard
def _media_badge(music_url: str | None, music_original_url: str | None):
    """
    Renvoie un badge {icon,label} pour affichage dans le dashboard.
    - Fichier local + origine YouTube => badge YouTube (local)
    - URL YouTube => badge YouTube
    - Autres plateformes… idem qu’avant
    - Fichier local sans origine => pas de badge
    """
    u = (music_url or "").strip().lower()
    orig = (music_original_url or "").strip().lower()

    # 1) Fichier local ?
    if u.startswith("/uploads/"):
        # S'il a été importé depuis YouTube, on met le même badge que pour les vidéos
        if "youtube.com" in orig or "youtu.be" in orig:
            return {"icon":"▶️","label":"YouTube (local)","class":"yt-local"}
        # sinon pas d'indicateur
        return None

    # 2) Liens externes (comme avant)
    if "youtube.com" in u or "youtu.be" in u:
        return {"icon": "▶️", "label": "YouTube"}
    if "open.spotify.com" in u:
        return {"icon": "🟢", "label": "Spotify"}
    if "soundcloud.com" in u:
        return {"icon": "☁️", "label": "SoundCloud"}
    if "deezer.com" in u or "link.deezer.com" in u:
        return {"icon": "🔷", "label": "Deezer"}
    if "music.apple.com" in u or "embed.music.apple.com" in u:
        return {"icon": "🍎", "label": "Apple Music"}
    if u.startswith("http") and any(u.endswith("."+ext) for ext in ["mp3","m4a","aac","ogg","opus","wav"]):
        return {"icon": "🎵", "label": "Audio"}
    if u.startswith("http"):
        return {"icon": "🌐", "label": "Lien"}

    return None



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

    # <- ajoute ce bloc
    pending = 0
    if getattr(current_user, "is_authenticated", False):
        try:
            fr = store.list_friendship(current_user.get_id())
            pending = len(fr.get("pending_in", []))
        except Exception:
            pending = 0
    # ->

    return {
        "now": datetime.utcnow,
        "site_name": conf.get("site_name", "Pastel Notes"),
        "has_spotify": has_spotify,
        "spotify_connected": spotify_connected,
        "friend_pending_count": pending,  # <--- nouveau
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
    try:
        rows = store.list_texts_accessible(current_user.get_id())
    except Exception:
        current_app.logger.exception("dashboard: list_texts_for_user failed")
        flash("Impossible d'afficher le tableau de bord.")
        return render_template("dashboard.html", texts=[])

    texts = []
    for r in rows:
        try:
            vm = _row_to_vm(r)
            # recharger le texte complet (pour always get created_by + cipher_*)
            full = store.get_text_dict(vm["id"]) or {}
            vm["created_by"] = full.get("created_by", vm["created_by"])

            # déchiffrer si possible
            title = vm["title"]; body = vm["body"]; context = vm["context"]
            if full.get("ciphertext") and full.get("cipher_nonce"):
                try:
                    clear = cserv.decrypt_text_payload(
                        full["created_by"], full["ciphertext"], full["cipher_nonce"]
                    )
                    title   = clear.get("title") or title
                    body    = clear.get("body")
                    context = clear.get("context")
                except Exception:
                    current_app.logger.warning("decrypt failed on text %s", vm["id"], exc_info=True)
                    title   = title or "(indéchiffrable)"
                    body    = "(indéchiffrable)"
                    context = None

            vm["title"]   = title or "(sans titre)"
            vm["body"]    = body
            vm["context"] = context

            mu = full.get("music_url") or r.get("music_url")
            morig = full.get("music_original_url") or r.get("music_original_url")
            vm["media_badge"] = _media_badge(mu, morig)

            # widget YT (si extraction en cours)
            try:
                yt = (read_db().get("jobs", {}).get("yt", {}) or {}).get(str(vm["id"]))
                if yt:
                    vm["yt_job_id"] = yt
            except Exception:
                pass

            texts.append(vm)
        except Exception:
            current_app.logger.exception("dashboard: failed to build VM for row=%r", r)
            # on skip juste ce texte

    texts.sort(key=lambda t: t["date_dt"], reverse=True)
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

    # 1) Config (depuis data.json) — on n’exporte que la config
    conf = get_conf(read_db())

    # 2) Lecture SQL
    with store.SessionLocal() as s:
        users = s.scalars(store.select(store.User)).all()
        texts = s.scalars(store.select(store.Text)).all()

        # relations optionnelles (si présentes dans le module)
        friends, friend_requests = [], []
        if hasattr(store, "Friend"):
            frs = s.scalars(store.select(store.Friend)).all()
            for fr in frs:
                friends.append({"user": s.get(store.User, fr.user_id).username,
                                "friend": s.get(store.User, fr.friend_user_id).username,
                                "created_at": fr.created_at.isoformat()})
        if hasattr(store, "FriendRequest"):
            rqs = s.scalars(store.select(store.FriendRequest)).all()
            for rq in rqs:
                friends.append if False else None
            for rq in rqs:
                friend_requests.append({
                    "from": s.get(store.User, rq.from_user_id).username,
                    "to": s.get(store.User, rq.to_user_id).username,
                    "status": rq.status,
                    "created_at": rq.created_at.isoformat(),
                    "responded_at": rq.responded_at.isoformat() if rq.responded_at else None
                })

        tokens = []
        if hasattr(store, "SpotifyToken"):
            toks = s.scalars(store.select(store.SpotifyToken)).all()
            for t in toks:
                u = s.get(store.User, t.user_id)
                tokens.append({
                    "username": u.username if u else None,
                    "access_token": t.access_token,
                    "refresh_token": t.refresh_token,
                    "expires_at": t.expires_at.isoformat() if t.expires_at else None,
                })

        # 3) Construire JSON
        payload = {
            "schema": 2,
            "exported_at": datetime.utcnow().isoformat(),
            "config": conf,  # seulement config depuis data.json
            "users": [{
                "username": u.username,
                "password_hash": u.password_hash,
                "email": u.email,
                "encrypted_user_key": u.encrypted_user_key,  # garde l’UDK scellée
                "is_admin": bool(u.is_admin),
                "created_at": u.created_at.isoformat() if u.created_at else None,
            } for u in users],
            "texts": [],
            "friends": friends,
            "friend_requests": friend_requests,
            "spotify_tokens": tokens,
        }

        assets_root = "assets"
        for t in texts:
            allowed_unames = [u.username for u in t.allowed_users]
            item = {
                "id": t.id,
                "cipher_alg": t.cipher_alg,
                "ciphertext": t.ciphertext,
                "cipher_nonce": t.cipher_nonce,
                "default_allow": bool(t.default_allow),
                "music_url": t.music_url,
                "music_original_url": t.music_original_url,
                "image_filename": t.image_filename,
                "image_url": t.image_url,
                "image_original_url": t.image_original_url,
                "date": t.date.isoformat() if t.date else None,
                "created_at": t.created_at.isoformat() if t.created_at else None,
                "updated_at": t.updated_at.isoformat() if t.updated_at else None,
                "created_by": t.created_by_user.username,
                "allowed_usernames": allowed_unames,
                "backup_assets": {}
            }
            # marquer assets à embarquer
            if t.music_url and isinstance(t.music_url, str) and t.music_url.startswith("/uploads/"):
                fname = t.music_url.split("/")[-1]
                item["backup_assets"]["music_file"] = _safe_join(assets_root, "music", fname)
                if not item.get("music_original_url"):
                    item["music_original_url"] = t.music_original_url
            if t.image_filename:
                item["backup_assets"]["image_file"] = _safe_join(assets_root, "images", t.image_filename)
                if not item.get("image_original_url"):
                    item["image_original_url"] = t.image_url

            payload["texts"].append(item)

    # 4) ZIP (assets + backup.json)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for t in payload["texts"]:
            ba = t.get("backup_assets") or {}
            # musique
            mf = ba.get("music_file")
            if mf:
                fname = os.path.basename(mf)
                _copy_into_zip(z, UPLOAD_DIR / fname, mf)
            # image
            imf = ba.get("image_file")
            if imf:
                fname = os.path.basename(imf)
                _copy_into_zip(z, UPLOAD_DIR / fname, imf)

        z.writestr("backup.json", json.dumps(payload, ensure_ascii=False, indent=2))

    buf.seek(0)
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return send_file(buf, as_attachment=True,
                     download_name=f"pastel_notes_backup_{stamp}.zip",
                     mimetype="application/zip")



# ------------------- Admin: Import (.json / .zip) -------------------

@core_bp.route("/admin/import", methods=["GET", "POST"])
@login_required
def admin_import():
    if not getattr(current_user, "is_admin", False):
        abort(403)

    if request.method != "POST":
        return render_template("import.html")

    # taille
    if request.content_length and request.content_length > MAX_IMPORT_MB * 1024 * 1024:
        flash(f"Fichier trop volumineux (> {MAX_IMPORT_MB} Mo).")
        return redirect(url_for("core.admin_import"))

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

    # 1) Config : on n’écrase PAS secret_key ni admin
    incoming_conf = (payload.get("config") or {})
    db_conf = get_conf(read_db())  # lecture actuelle
    for k, v in incoming_conf.items():
        if k in {"secret_key", "admin"}:
            continue
        # écriture via ta CLI existante si tu veux, sinon laisse tel quel (config reste dans data.json)
        # ex: app.py config-set … (facultatif)

    # 2) SQL : transaction
    added_users = added_texts = added_access = 0

    with store.SessionLocal.begin() as s:
        # (optionnel) purge
        if replace_all:
            if hasattr(store, "SpotifyToken"):
                s.execute(store.sa.delete(store.SpotifyToken))
            if hasattr(store, "Friend"):
                s.execute(store.sa.delete(store.Friend))
            if hasattr(store, "FriendRequest"):
                s.execute(store.sa.delete(store.FriendRequest))
            s.execute(store.sa.delete(store.text_access))
            s.execute(store.sa.delete(store.Text))
            s.execute(store.sa.delete(store.User))

        # index auxiliaires
        def _get_user(uname: str):
            return s.scalar(store.select(store.User).where(store.sa.func.lower(store.User.username)==uname.strip().lower()))

        # Users
        for u in (payload.get("users") or []):
            uname = (u.get("username") or "").strip()
            if not uname:
                continue
            if _get_user(uname):
                continue
            row = store.User(
                username=uname,
                password_hash=u.get("password_hash") or "",
                email=u.get("email"),
                encrypted_user_key=u.get("encrypted_user_key"),
                is_admin=bool(u.get("is_admin")),
                created_at=datetime.fromisoformat(u["created_at"]) if u.get("created_at") else datetime.utcnow()
            )
            s.add(row); added_users += 1
        s.flush()

        # s'assurer que l'admin défini en config existe et est admin
        adm = (incoming_conf.get("admin") or db_conf.get("admin") or {}).get("username")
        if adm:
            uadm = _get_user(adm)
            if not uadm:
                uadm = store.User(username=adm, password_hash="", is_admin=True, created_at=datetime.utcnow())
                s.add(uadm); added_users += 1
            else:
                uadm.is_admin = True

        # Textes (fusion par empreinte)
        # on construit un set des empreintes existantes
        existing = set()
        for t in s.scalars(store.select(store.Text)).all():
            d = {
                "created_by": t.created_by_user.username,
                "date": t.date.isoformat() if t.date else "",
                "ciphertext": t.ciphertext,
                "title": t.title, "body": t.body
            }
            existing.add(_text_fingerprint_dict(d))

        for t in (payload.get("texts") or []):
            # map auteur
            author = _get_user(t.get("created_by") or "")
            if not author:
                author = store.User(username=t.get("created_by") or "unknown", password_hash="", is_admin=False, created_at=datetime.utcnow())
                s.add(author); s.flush(); added_users += 1

            # assets (si zip)
            ba = t.get("backup_assets") or {}
            new_music_url = t.get("music_url")
            new_image_filename = t.get("image_filename")

            if zf and ba.get("music_file"):
                nm = _import_asset_from_zip(zf, ba["music_file"])
                if nm:
                    new_music_url = f"/uploads/{nm}"
            if zf and ba.get("image_file"):
                ni = _import_asset_from_zip(zf, ba["image_file"])
                if ni:
                    new_image_filename = ni

            new_dict = {
                "created_by": author.username,
                "date": t.get("date") or "",
                "ciphertext": t.get("ciphertext"),
                "title": t.get("title"),
                "body": t.get("body"),
            }
            fp = _text_fingerprint_dict(new_dict)
            if not replace_all and fp in existing:
                continue

            row = store.Text(
                cipher_alg=t.get("cipher_alg"),
                ciphertext=t.get("ciphertext"),
                cipher_nonce=t.get("cipher_nonce"),
                default_allow=bool(t.get("default_allow") or False),
                music_url=new_music_url,
                music_original_url=t.get("music_original_url"),
                image_filename=new_image_filename,
                image_url=t.get("image_url"),
                image_original_url=t.get("image_original_url"),
                date=datetime.fromisoformat(t["date"]) if t.get("date") else datetime.utcnow(),
                created_at=datetime.fromisoformat(t["created_at"]) if t.get("created_at") else datetime.utcnow(),
                updated_at=datetime.fromisoformat(t["updated_at"]) if t.get("updated_at") else datetime.utcnow(),
                created_by_id=author.id
            )
            s.add(row); s.flush()
            added_texts += 1

            # permissions
            for uname in (t.get("allowed_usernames") or []):
                u = _get_user(uname)
                if not u:
                    continue
                # existe déjà ?
                seen = s.execute(store.sa.select(store.text_access.c.text_id)
                                 .where(store.text_access.c.text_id==row.id,
                                        store.text_access.c.user_id==u.id)).first()
                if not seen:
                    s.execute(store.sa.insert(store.text_access).values(text_id=row.id, user_id=u.id))
                    added_access += 1

        # Spotify tokens
        for tok in (payload.get("spotify_tokens") or []):
            uname = tok.get("username")
            if not uname: continue
            u = _get_user(uname)
            if not u: continue
            if hasattr(store, "SpotifyToken"):
                old = s.get(store.SpotifyToken, u.id)
                if old: s.delete(old)
                s.add(store.SpotifyToken(
                    user_id=u.id,
                    access_token=tok.get("access_token"),
                    refresh_token=tok.get("refresh_token"),
                    expires_at=datetime.fromisoformat(tok["expires_at"]) if tok.get("expires_at") else None
                ))

    # UDK pour les nouveaux users (si tu utilises le chiffrement serveur)
    try:
        import crypto_server as cserv
        cserv.ensure_all_user_udk()
    except Exception:
        pass

    flash(f"Import terminé. Users+{added_users}, Textes+{added_texts}, Permissions+{added_access}.")
    return redirect(url_for("core.dashboard"))
