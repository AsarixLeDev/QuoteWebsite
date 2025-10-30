# routes_exports.py
from __future__ import annotations

import io
from pathlib import Path
from flask import Blueprint, send_file, request, abort, current_app
from flask_login import login_required, current_user

import storage_sql as store
import crypto_server as cserv
from export_utils import export_pdf_bytes, export_docx_bytes

exports_bp = Blueprint("exports", __name__)

def _decrypt_for_export(t: dict) -> dict:
    """Retourne un dict prêt à exporter (titre/contexte/corps déchiffrés)."""
    out = dict(t)
    if t.get("ciphertext") and t.get("cipher_nonce"):
        try:
            clear = cserv.compat_decrypt_and_rewrap_row(t)
            out["title"] = clear.get("title") or t.get("title")
            out["body"] = clear.get("body") or ""
            out["context"] = clear.get("context")
        except Exception:
            out["body"] = out.get("body") or ""
    else:
        out["body"] = out.get("body") or ""
    return out

def _logo_path() -> Path:
    """Chemin par défaut du logo côté app (à adapter si tu veux)."""
    root = Path(current_app.root_path)
    p = root / "static" / "brand" / "pastelnotes-mark.png"
    if p.exists():
        return p
    p = root / "static" / "img" / "pastelnotes-logo-512.png"
    return p

def _can_view(text_id: int) -> bool:
    """Réutilise ta logique d'accès “lecture” (amis/public/explicite)."""
    # Admin → ok
    if getattr(current_user, "is_admin", False):
        return True
    return store.can_user_view_text(current_user.get_id(), text_id)

@exports_bp.route("/texts/<int:text_id>/export/pdf")
@login_required
def export_text_pdf(text_id: int):
    t = store.get_text_dict(text_id)
    if not t:
        abort(404)
    if not _can_view(text_id):
        abort(403)

    data = _decrypt_for_export(t)
    base_url = request.url_root.rstrip("/")   # pour réécrire /uploads en absolu
    pdf = export_pdf_bytes(data, logo_path=_logo_path(), base_url=base_url)

    # nom de fichier sûr
    fname = (data.get("title") or "pastelnotes").strip() or "pastelnotes"
    safe = "".join(ch if ch.isalnum() or ch in " _-" else "_" for ch in fname)[:80] + ".pdf"

    return send_file(io.BytesIO(pdf),
                     mimetype="application/pdf",
                     as_attachment=True,
                     download_name=safe)

@exports_bp.route("/texts/<int:text_id>/export/docx")
@login_required
def export_text_docx(text_id: int):
    t = store.get_text_dict(text_id)
    if not t:
        abort(404)
    if not _can_view(text_id):
        abort(403)

    data = _decrypt_for_export(t)
    docx = export_docx_bytes(data, logo_path=_logo_path())

    fname = (data.get("title") or "pastelnotes").strip() or "pastelnotes"
    safe = "".join(ch if ch.isalnum() or ch in " _-" else "_" for ch in fname)[:80] + ".docx"

    return send_file(io.BytesIO(docx),
                     mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                     as_attachment=True,
                     download_name=safe)
