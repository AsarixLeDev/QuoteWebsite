from __future__ import annotations

from datetime import datetime

from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
import storage_sql as store
import crypto_server as cserv

friends_bp = Blueprint("friends", __name__)

@friends_bp.route("/friends", methods=["GET"])
@login_required
def friends_home():
    data = store.list_friendship(current_user.get_id())
    return render_template("friends.html", data=data)

@friends_bp.route("/friends/request", methods=["POST"])
@login_required
def friends_request():
    to = (request.form.get("to") or "").strip()
    if not to:
        flash("Nom d'utilisateur requis."); return redirect(url_for("friends.friends_home"))
    try:
        store.send_friend_request(current_user.get_id(), to)
        flash("Demande envoyée (ou amitié acceptée si une demande inverse existait).")
    except ValueError as e:
        flash(str(e))
    return redirect(url_for("friends.friends_home"))

@friends_bp.route("/friends/cancel", methods=["POST"])
@login_required
def friends_cancel():
    other = (request.form.get("other") or "").strip()
    store.cancel_friend_request(current_user.get_id(), other)
    flash("Demande annulée.")
    return redirect(url_for("friends.friends_home"))

@friends_bp.route("/friends/respond", methods=["POST"])
@login_required
def friends_respond():
    other = (request.form.get("other") or "").strip()
    accept = (request.form.get("accept") == "1")
    try:
        store.respond_friend_request(current_user.get_id(), other, accept)
        flash("Demande traitée.")
    except ValueError as e:
        flash(str(e))
    return redirect(url_for("friends.friends_home"))

@friends_bp.route("/friends/remove", methods=["POST"])
@login_required
def friends_remove():
    other = (request.form.get("other") or "").strip()
    store.remove_friend(current_user.get_id(), other)
    flash("Ami supprimé.")
    return redirect(url_for("friends.friends_home"))

@friends_bp.route("/u/<username>/texts", methods=["GET"])
@login_required
def friend_texts(username: str):
    rows = store.list_texts_visible_to(current_user.get_id(), username)

    vms = []
    for obj in rows:
        tid = obj.id if hasattr(obj, "id") else obj.get("id")
        if not tid:
            continue
        # Ceinture-bretelles
        if not store.can_user_view_text(current_user.get_id(), tid):
            continue

        full = store.get_text_dict(tid)
        if not full:
            continue

        # Déchiffrage pour l'aperçu
        import crypto_server as cserv
        title, body, context = full.get("title"), None, None
        if full.get("ciphertext") and full.get("cipher_nonce"):
            try:
                clear = cserv.compat_decrypt_and_rewrap_row(full)
                title   = clear.get("title") or title
                body    = clear.get("body")
                context = clear.get("context")
            except Exception:
                title = title or "(indéchiffrable)"; body="(indéchiffrable)"; context=None

        vms.append({
            "id": full["id"],
            "title": title or "(sans titre)",
            "body": body,
            "context": context,
            "date_dt": datetime.fromisoformat(full["date"]) if full.get("date") else datetime.utcnow(),
            "image_filename": full.get("image_filename"),
            "image_url": full.get("image_url"),
        })

    return render_template("friend_texts.html", friend=username, texts=vms)