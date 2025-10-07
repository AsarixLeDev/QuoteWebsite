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


def _yt_map_set(text_id: int, job_id: str) -> None:
    db = read_db()
    db.setdefault("jobs", {}).setdefault("yt", {})[str(text_id)] = job_id
    write_db(db)

def _yt_map_get(text_id: int) -> str | None:
    return (read_db().get("jobs", {}).get("yt", {}) or {}).get(str(text_id)) or None

def _yt_map_find_text_id(job_id: str) -> int | None:
    m = (read_db().get("jobs", {}).get("yt", {}) or {})
    for k, v in m.items():
        if v == job_id:
            try: return int(k)
            except: return None
    return None


def _yt_job_id_for(text_id: int) -> str | None:
    """Retourne l'id de job yt-dlp pour un texte depuis data.json (mapping job)."""
    try:
        mapping = (read_db().get("jobs", {}).get("yt", {}) or {})
        v = mapping.get(str(text_id))
        return v or None
    except Exception:
        return None

def _compute_embed_for_view(t: dict) -> dict:
    """
    Règle d'affichage:
      - Si fichier local (/uploads/xxx) -> audio_direct
      - Si music_original_url est YouTube ET pas de fichier local -> extraction en cours -> pas d'embed, on affiche le widget
      - Sinon: détection standard (_detect_embed) sur music_url puis music_original_url
    """
    u = t.get("music_url")
    if u and isinstance(u, str) and u.startswith("/uploads/"):
        return {"type": "audio_direct", "src": u}
    # extraction YT audio en cours ?
    if _is_youtube(t.get("music_original_url")) and not t.get("music_url"):
        return {"type": "pending", "src": None}
    src = t.get("music_url") or t.get("music_original_url")
    return _detect_embed(src)


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
    allowed = store.can_user_view_text(current_user.get_id(), text_id)
    if not allowed:
        from flask import abort
        abort(403)

    # VM
    vm = dict(t)
    vm["date_dt"] = datetime.fromisoformat(t["date"]) if t.get("date") else datetime.utcnow()

    # déchiffre pour l’affichage
    import crypto_server as cserv
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

    # embed / widget: priorité au fichier local; si YT audio en cours => widget
    vm["embed"] = _compute_embed_for_view(t)

    # job id (si extraction YT en cours)
    vm["yt_job_id"] = _yt_map_get(int(t["id"]))  # pour le polling
    vm["yt_audio_pending"] = bool(_is_youtube(t.get("music_original_url")) and not t.get("music_url"))

    # état spotify (si tu l’utilises)
    try:
        vm["spotify_connected"] = bool(get_spotify_token_record(read_db(), current_user.get_id()))
    except Exception:
        vm["spotify_connected"] = False

    return render_template("text_view.html", text=vm)


@texts_bp.route("/texts/new", methods=["GET", "POST"])
@login_required
def new_text():
    # Tous les utilisateurs peuvent créer
    usernames = store.all_usernames()
    # Exemple: si tu veux éviter de proposer le créateur lui-même:
    try:
        me = current_user.get_id()
        usernames = [u for u in usernames if u.strip().lower() != me.strip().lower()]
    except Exception:
        pass

    if request.method == "POST":
        if request.content_length and request.content_length > MAX_UPLOAD_MB * 1024 * 1024:
            flash(f"Fichier trop volumineux (> {MAX_UPLOAD_MB} Mo).")
            return render_template("text_form.html", is_new=True, users=usernames, text=None)

        title = _clean_opt(request.form.get("title"))
        body = request.form.get("body")
        context_val = _clean_opt(request.form.get("context"))
        if not body:
            flash("Le texte est requis.")
            return render_template("text_form.html", is_new=True, users=usernames, text=None)

        # Date
        date_str = (request.form.get("date") or "").strip()
        dt = datetime.utcnow()
        if date_str:
            try:
                dt = datetime.strptime(date_str, "%Y-%m-%dT%H:%M")
            except ValueError:
                flash("Format de date invalide.")
                return render_template("text_form.html", is_new=True, users=usernames, text=None)

        # Image
        img_fs = request.files.get("image_file")
        img_name = _save_upload(img_fs, ALLOWED_IMAGE_EXTS) if img_fs and img_fs.filename else None
        image_remote_url = _clean_opt(request.form.get("image_url"))

        # Musique
        mus_fs = request.files.get("music_file")
        link = _clean_opt(request.form.get("music_url"))
        want_yt_audio = (request.form.get("youtube_audio") == "1")

        music_url = None              # ce qui sera lu par l'embed audio local SI présent
        music_original_url = None     # on garde l'URL d'origine (YouTube / autre)

        if mus_fs and mus_fs.filename:
            mname = _save_upload(mus_fs, ALLOWED_AUDIO_EXTS)
            if mname:
                music_url = f"/uploads/{mname}"
        elif link:
            if _is_youtube(link):
                if want_yt_audio:
                    # Extraction audio -> pas d'embed vidéo : on laisse music_url=None et on garde l'original
                    music_original_url = link
                else:
                    # Mode vidéo : on embarque YouTube directement
                    music_url = link
            else:
                music_url = link

        # Permissions
        all_users = store.all_usernames()  # exclut admin
        allowed_final = [u for u in request.form.getlist("allowed_users") if u in all_users]

        # Chiffrement (titre/corps/contexte) – on suppose crypto_server importé en haut
        import crypto_server as cserv
        clear = {"title": title, "body": body, "context": context_val}
        enc = cserv.encrypt_text_payload(current_user.get_id(), clear)

        # Création SQL
        text_id = store.create_text(
            created_by_username=current_user.get_id(),
            data={
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
            allowed_usernames=allowed_final
        )

        # Si on a demandé YT audio -> on lance le job maintenant
        if music_original_url and _is_youtube(music_original_url) and not music_url:
            job_id = jobs.enqueue_yt_audio(text_id, music_original_url)
            _yt_map_set(text_id, job_id)

        flash("Texte créé.")
        return redirect(url_for("texts.view_text", text_id=text_id))

    return render_template("text_form.html", is_new=True, users=usernames, text=None)



@texts_bp.route("/texts/<int:text_id>/edit", methods=["GET", "POST"])
@login_required
def edit_text(text_id: int):
    # Seul l’auteur peut modifier
    t = store.get_text_dict(text_id)
    if not t:
        from flask import abort; abort(404)
    me = (current_user.get_id() or "").strip().lower()
    author = (t.get("created_by") or "").strip().lower()
    if me != author:
        from flask import abort; abort(403)

    # GET -> préremplissage avec déchiffrement
    if request.method == "GET":
        # déchiffre pour le formulaire
        import crypto_server as cserv
        title, body, context = t.get("title"), t.get("body"), t.get("context")
        if t.get("ciphertext") and t.get("cipher_nonce"):
            try:
                clear = cserv.decrypt_text_payload(t["created_by"], t["ciphertext"], t["cipher_nonce"])
                title = clear.get("title") or title
                body = clear.get("body")
                context = clear.get("context")
            except Exception:
                pass

        vm = dict(t)
        vm["title"] = title or ""
        vm["body"] = body or ""
        vm["context"] = context or ""
        vm["date_dt"] = datetime.fromisoformat(t["date"]) if t.get("date") else datetime.utcnow()

        # Valeur à afficher dans le champ URL musique (si c’est une URL distante)
        mv = ""
        if t.get("music_original_url"):
            mv = t["music_original_url"]
        else:
            u = t.get("music_url")
            if u and not str(u).startswith("/uploads/"):
                mv = u
        vm["music_input_value"] = mv

        # Le switch "YouTube audio" est coché si audio en extraction (original YouTube + pas de fichier local)
        vm["youtube_audio_checked"] = bool(_is_youtube(t.get("music_original_url")) and not t.get("music_url"))

        # Permissions possibles
        usernames = store.all_usernames()
        # Exemple: si tu veux éviter de proposer le créateur lui-même:
        try:
            me = current_user.get_id()
            usernames = [u for u in usernames if u.strip().lower() != me.strip().lower()]
        except Exception:
            pass
        return render_template("text_form.html", is_new=False, users=usernames, text=vm)

    # POST -> mise à jour
    # Champs texte
    title = _clean_opt(request.form.get("title"))
    body = request.form.get("body")
    context_val = _clean_opt(request.form.get("context"))
    if not body:
        flash("Le texte est requis.")
        # Rejoue le GET pour préremplir
        return redirect(url_for("texts.edit_text", text_id=text_id))

    # Date
    date_str = (request.form.get("date") or "").strip()
    dt = None
    if date_str:
        try:
            dt = datetime.strptime(date_str, "%Y-%m-%dT%H:%M")
        except ValueError:
            flash("Format de date invalide.")
            return redirect(url_for("texts.edit_text", text_id=text_id))

    # Images
    img_fs = request.files.get("image_file")
    image_remote_url = _clean_opt(request.form.get("image_url"))

    new_image_filename = t.get("image_filename")
    new_image_url = t.get("image_url")
    new_image_original_url = t.get("image_original_url")

    if img_fs and img_fs.filename:
        nm = _save_upload(img_fs, ALLOWED_IMAGE_EXTS)
        if nm:
            new_image_filename = nm
            new_image_url = None
    elif image_remote_url:
        # si pas de fichier local, on peut mettre/mettre à jour une URL distante
        if not new_image_filename:
            new_image_url = image_remote_url
            if not new_image_original_url:
                new_image_original_url = image_remote_url

    # Musique
    mus_fs = request.files.get("music_file")
    link = _clean_opt(request.form.get("music_url"))
    want_yt_audio = (request.form.get("youtube_audio") == "1")

    old_music_url = t.get("music_url")
    old_music_original = t.get("music_original_url")

    new_music_url = old_music_url
    new_music_original = old_music_original

    if mus_fs and mus_fs.filename:
        mname = _save_upload(mus_fs, ALLOWED_AUDIO_EXTS)
        if mname:
            new_music_url = f"/uploads/{mname}"
            new_music_original = None
    elif link is not None:
        # input fourni (peut être vide pour "clear" -> on garde l'ancien si vide)
        if link == "":
            pass  # ne rien changer si champ vidé
        else:
            if _is_youtube(link):
                if want_yt_audio:
                    new_music_url = None
                    new_music_original = link
                else:
                    new_music_url = link
                    new_music_original = None
            else:
                new_music_url = link
                new_music_original = None

    # Permissions
    all_users = store.all_usernames()  # exclut admin
    allowed_final = [u for u in request.form.getlist("allowed_users") if u in all_users]

    # Chiffrement (re-écrit toujours la version claire)
    import crypto_server as cserv
    clear = {"title": title, "body": body, "context": context_val}
    enc = cserv.encrypt_text_payload(t["created_by"], clear)

    # Mise à jour SQL
    payload = {
        "cipher_alg": enc["cipher_alg"],
        "ciphertext": enc["ciphertext"],
        "cipher_nonce": enc["cipher_nonce"],
        "music_url": new_music_url,
        "music_original_url": new_music_original,
        "image_filename": new_image_filename,
        "image_url": new_image_url,
        "image_original_url": new_image_original_url,
    }
    if dt:
        payload["date_dt"] = dt
    store.update_text(text_id, payload, allowed_final)

    # (Ré)lancer job YT si on est en mode audio (original youtube + pas de fichier local)
    if new_music_original and _is_youtube(new_music_original) and not new_music_url:
        job_id = jobs.enqueue_yt_audio(text_id, new_music_original)
        _yt_map_set(text_id, job_id)

    flash("Texte mis à jour.")
    return redirect(url_for("texts.view_text", text_id=text_id))

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
    if j:
        return jsonify({
            "id": j["id"], "state": j["state"],
            "progress": j["progress"], "message": j.get("message","")
        })
    # pas en mémoire -> peut-être redémarrage : retrouve le texte
    tid = _yt_map_find_text_id(job_id)
    if tid:
        t = store.get_text_dict(tid)
        # si extraction toujours nécessaire (YT original présent, pas de fichier local)
        if t and _is_youtube(t.get("music_original_url")) and not t.get("music_url"):
            return jsonify({"id": job_id, "state": "missing", "progress": 0,
                            "message": "Service relancé — cliquez Relancer"}), 200
    return jsonify({"state": "unknown"}), 404


def _is_owner(text_id:int) -> bool:
    t = store.get_text_dict(text_id)
    return bool(t and (t.get("created_by") or "").strip().lower() == (current_user.get_id() or "").strip().lower())

@texts_bp.route("/jobs/<job_id>/cancel", methods=["POST"])
@login_required
def job_cancel(job_id: str):
    tid = _yt_map_find_text_id(job_id)
    if not (getattr(current_user, "is_admin", False) or (tid and _is_owner(tid))):
        return jsonify({"error":"forbidden"}), 403
    ok = jobs.cancel_job(job_id)
    return jsonify({"ok": bool(ok)}), (200 if ok else 404)

@texts_bp.route("/jobs/<job_id>/retry", methods=["POST"])
@login_required
def job_retry(job_id: str):
    tid = _yt_map_find_text_id(job_id)
    if not (tid and (getattr(current_user, "is_admin", False) or _is_owner(tid))):
        return jsonify({"error":"forbidden"}), 403
    t = store.get_text_dict(tid)
    if not t: return jsonify({"error":"unknown_text"}), 404
    # relance propre à partir de l'URL originale
    if not (_is_youtube(t.get("music_original_url")) and not t.get("music_url")):
        return jsonify({"error":"no_pending"}), 400
    new_id = jobs.enqueue_yt_audio(tid, t["music_original_url"])
    _yt_map_set(tid, new_id)
    return jsonify({"ok": True, "job_id": new_id})
