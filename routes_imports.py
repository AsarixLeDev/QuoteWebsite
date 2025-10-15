# routes_imports.py
from __future__ import annotations
import io, re, json, zipfile, tempfile
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, List

from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

import storage_sql as store
from paths import UPLOAD_DIR
import crypto_server as cserv

try:
    from docx import Document as DocxDocument
except Exception:
    DocxDocument = None

try:
    from pdfminer.high_level import extract_text as pdf_extract_text
except Exception:
    pdf_extract_text = None

importer_bp = Blueprint("importer", __name__)

ALLOWED_IMPORT = {"docx", "pdf", "txt", "md", "html", "htm", "zip"}

def _save_bytes_to_uploads(data: bytes, ext: str) -> str:
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    name = secure_filename(f"imp_{current_user.get_id()}_{store.datetime.datetime.utcnow().timestamp()}").replace(".","")
    fname = f"{name}.{ext}"
    (UPLOAD_DIR / fname).write_bytes(data)
    return fname

def _heuristic_music(s: str) -> Optional[str]:
    m = re.search(r'(https?://[^\s]+)', s)
    if not m: return None
    url = m.group(1)
    if any(k in url for k in ["youtube.com","youtu.be","open.spotify.com","deezer.com","soundcloud.com","music.apple.com"]):
        return url
    return None

def _normalize_parts(title: Optional[str], context: Optional[str], body: Optional[str]) -> Dict[str, Optional[str]]:
    title = (title or "").strip() or None
    context = (context or "").strip() or None
    body = (body or "").strip() or None
    return {"title": title, "context": context, "body": body}

# --------- Parsers ----------
def parse_docx(data: bytes) -> Tuple[Dict[str,Optional[str]], Optional[bytes], Optional[str], Optional[str]]:
    """
    Retourne: (parts{title,context,body}, image_bytes (1ère), image_ext, music_url)
    """
    if not DocxDocument:
        raise RuntimeError("python-docx non installé.")
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "f.docx"
        p.write_bytes(data)
        doc = DocxDocument(str(p))

    title = None; context = None; body_lines: List[str] = []
    music = None

    # Essais : 1er heading = title, 1er italic = context, sinon heuristiques
    for para in doc.paragraphs:
        txt = para.text.strip()
        if not txt: continue
        if (para.style and para.style.name and para.style.name.startswith("Heading")) and not title:
            title = txt; continue
        if any(r.italic for r in para.runs) and not context:
            context = txt; continue
        body_lines.append(txt)
        if not music:
            mu = _heuristic_music(txt)
            if mu: music = mu

    # Images (1ère uniquement)
    image_bytes = None; image_ext = None
    # python-docx n’expose pas direct les bytes via API publique; on parcourt media
    try:
        rels = doc.part._rels  # type: ignore
        for r in rels.values():
            if "image" in r.target_ref:
                # lit le binaire
                image_part = r._target.part  # type: ignore
                blob = image_part.blob
                image_bytes = blob
                # devine extension
                try:
                    img = Image.open(io.BytesIO(blob))
                    image_ext = img.format.lower()  # 'jpeg','png'...
                    if image_ext == "jpeg": image_ext = "jpg"
                except Exception:
                    image_ext = "bin"
                break
    except Exception:
        pass

    parts = _normalize_parts(title, context, "\n".join(body_lines).strip())
    return parts, image_bytes, image_ext, music

def parse_pdf(data: bytes) -> Tuple[Dict[str,Optional[str]], None, None, Optional[str]]:
    if not pdf_extract_text:
        raise RuntimeError("pdfminer.six non installé.")
    text = pdf_extract_text(io.BytesIO(data)) or ""
    # Titre = 1ère ligne non vide ; Contexte = 1ère ligne italique (introuvable) ou entre parenthèses au début
    lines = [l.strip() for l in text.splitlines()]
    lines = [l for l in lines if l]
    title = lines[0] if lines else None
    context = None
    if len(lines) > 1 and (lines[1].startswith("(") and lines[1].endswith(")")):
        context = lines[1][1:-1]
        body = "\n".join(lines[2:])
    else:
        body = "\n".join(lines[1:])
    music = _heuristic_music(text)
    return _normalize_parts(title, context, body), None, None, music

def parse_txt_like(data: bytes) -> Tuple[Dict[str,Optional[str]], None, None, Optional[str]]:
    s = data.decode("utf-8", errors="ignore")
    # iPhone Notes souvent: 1ère ligne titre, puis contenu
    lines = [l.rstrip() for l in s.splitlines()]
    title = (lines[0].strip() if lines and lines[0].strip() else None)
    # Contexte: ligne commençant par "Contexte:" ou entre ()
    context = None
    for l in lines[1:4]:
        if not l: continue
        if l.lower().startswith("contexte:"):
            context = l.split(":",1)[1].strip(); break
        if l.startswith("(") and l.endswith(")"):
            context = l[1:-1]; break
    body = "\n".join(lines[1:])
    music = _heuristic_music(s)
    return _normalize_parts(title, context, body), None, None, music

def parse_zip_export(data: bytes) -> Tuple[Dict[str,Optional[str]], Optional[bytes], Optional[str], Optional[str]]:
    """ZIP export PastelNotes (HTML+assets). Lit PNMETA si présent."""
    with zipfile.ZipFile(io.BytesIO(data), "r") as z:
        # backup “export.html” (si présent)
        meta = None
        # cherche PNMETA dans export.html
        for name in z.namelist():
            if name.endswith(".html"):
                html = z.read(name).decode("utf-8", errors="ignore")
                m = re.search(r"PNMETA:(\{.*\})", html)
                if m:
                    try: meta = json.loads(m.group(1)); break
                    except Exception: pass
        # on n’extrait pas d’image ici (meilleur : docx); on laissera l’URL si meta l’avait
        # pour le contenu, on peut simplifier: pas d’extraction HTML → on laisse vide et meta guidera
        parts = {"title": None, "context": None, "body": None}
        music = None
        if meta:
            music = meta.get("music_original_url") or meta.get("music_url")
        return parts, None, None, music

# --------- Route ----------
@importer_bp.route("/texts/import", methods=["GET","POST"])
@login_required
def import_text():
    if request.method == "GET":
        # liste d’amis acceptés pour permissions
        fr = store.list_friendship(current_user.get_id())
        friends = sorted(fr.get("accepted", []))
        return render_template("import_text.html", friends=friends)

    f = request.files.get("file")
    is_public = (request.form.get("default_allow") == "1")
    allowed_raw = request.form.getlist("allowed_users")
    friends = store.list_friendship(current_user.get_id())
    friends_set = set(friends.get("accepted", []))
    allowed_final = [u for u in allowed_raw if u in friends_set]

    if not f or not f.filename:
        flash("Choisis un fichier à importer.")
        return redirect(url_for("importer.import_text"))

    ext = (f.filename.rsplit(".",1)[-1].lower() if "." in f.filename else "")
    if ext not in ALLOWED_IMPORT:
        flash("Format non supporté. Utilise .docx, .pdf, .txt, .md, .html, .zip")
        return redirect(url_for("importer.import_text"))

    data = f.read()
    parts: Dict[str, Optional[str]]; img_bytes=None; img_ext=None; music=None

    try:
        if ext == "docx":
            parts, img_bytes, img_ext, music = parse_docx(data)
        elif ext == "pdf":
            parts, img_bytes, img_ext, music = parse_pdf(data)
        elif ext in {"txt","md","html","htm"}:
            parts, img_bytes, img_ext, music = parse_txt_like(data)
        elif ext == "zip":
            parts, img_bytes, img_ext, music = parse_zip_export(data)
        else:
            parts, img_bytes, img_ext, music = parse_txt_like(data)
    except RuntimeError as e:
        flash(str(e)); return redirect(url_for("importer.import_text"))

    # Sauvegarde image si on en a une
    img_name = None
    if img_bytes:
        ext2 = img_ext or "jpg"
        img_name = _save_bytes_to_uploads(img_bytes, ext2)

    # Musique
    music_url = None
    music_original_url = None
    if music:
        # Si YouTube: laisse en original (pour que l’owner puisse éventuellement l’extraire)
        music_original_url = music
    # Sinon rien → l’utilisateur pourra éditer plus tard

    # Corps / Contexte / Titre (et chiffrement)
    clear = {"title": parts.get("title"), "body": parts.get("body") or "", "context": parts.get("context")}
    enc = cserv.encrypt_text_payload(current_user.get_id(), clear)

    # Crée le texte
    tid = store.create_text(
        created_by_username=current_user.get_id(),
        data={
            "cipher_alg": enc["cipher_alg"],
            "ciphertext": enc["ciphertext"],
            "cipher_nonce": enc["cipher_nonce"],
            "default_allow": is_public,
            "music_url": music_url,
            "music_original_url": music_original_url,
            "image_filename": img_name,
            "image_url": None,
            "image_original_url": None,
        },
        allowed_usernames=allowed_final
    )

    flash("Import terminé.")
    return redirect(url_for("texts.view_text", text_id=tid))
