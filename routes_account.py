# routes_account.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from datetime import datetime, timedelta
import secrets

from storage_sql import SessionLocal, select, User, sa, set_user_password

account_bp = Blueprint("account", __name__)

# 1) Change password (user knows the current password)
@account_bp.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        cur = request.form.get("current_password","")
        new1 = request.form.get("new_password","")
        new2 = request.form.get("new_password2","")
        if not new1 or new1 != new2:
            flash("Les nouveaux mots de passe ne correspondent pas."); return redirect(url_for(".change_password"))
        # verify old password
        with SessionLocal() as s:
            u = s.scalar(select(User).where(User.username==current_user.get_id()))
            if not u or not u.check_password(cur):  # implement check_password on model
                flash("Mot de passe actuel invalide."); return redirect(url_for(".change_password"))
        set_user_password(current_user.get_id(), new1)
        flash("Mot de passe changé.")
        return redirect(url_for("core.dashboard"))
    return render_template("account_change_password.html")

# 2) Ask a reset link (forgotten password)
@account_bp.route("/account/password/forgot", methods=["GET","POST"])
def forgot_password():
    if request.method == "POST":
        username_or_email = (request.form.get("login") or "").strip()
        with SessionLocal.begin() as s:
            q = select(User).where( (User.username==username_or_email) | (User.email==username_or_email) )
            u = s.scalar(q)
            if u:
                token = secrets.token_urlsafe(32)
                exp = datetime.utcnow() + timedelta(hours=2)
                s.execute(sa.text("""
                  INSERT INTO password_resets (user_id, token, expires_at, used, created_at)
                  VALUES (:uid, :t, :exp, 0, :now)
                """), dict(uid=u.id, t=token, exp=exp.isoformat(), now=datetime.utcnow().isoformat()))
                _send_reset_email(u, token)  # implement below
        flash("Si un compte correspond, un lien de réinitialisation a été envoyé.")
        return redirect(url_for("auth.login"))
    return render_template("account_forgot.html")

# 3) Open reset link and set new password
@account_bp.route("/account/password/reset/<token>", methods=["GET","POST"])
def reset_with_token(token: str):
    with SessionLocal.begin() as s:
        row = s.execute(sa.text("""
            SELECT pr.id, pr.user_id, pr.expires_at, pr.used, u.username
            FROM password_resets pr JOIN users u ON u.id=pr.user_id
            WHERE pr.token=:t
        """), dict(t=token)).mappings().first()
        if not row:
            abort(404)
        if row["used"]:
            flash("Lien déjà utilisé."); return redirect(url_for("auth.login"))
        if datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
            flash("Lien expiré."); return redirect(url_for("account.forgot_password"))

        if request.method == "POST":
            p1 = request.form.get("new_password","")
            p2 = request.form.get("new_password2","")
            if not p1 or p1 != p2:
                flash("Les mots de passe ne correspondent pas."); return redirect(request.url)
            set_user_password(row["username"], p1)
            s.execute(sa.text("UPDATE password_resets SET used=1 WHERE id=:i"), dict(i=row["id"]))
            flash("Mot de passe réinitialisé.")
            return redirect(url_for("auth.login"))
    return render_template("account_reset.html", token=token)

def _send_reset_email(user, token: str):
    """
    Minimal sender:
    - If SMTP configured -> send an email
    - Else: log the URL to console (and flash generic message)
    """
    try:
        base = request.url_root.rstrip("/")
    except Exception:
        base = ""
    link = f"{base}/account/password/reset/{token}"
    print("Reset link for %s: %s", user.username, link)
    # TODO: integrate your SMTP settings; until then, link is in logs.
