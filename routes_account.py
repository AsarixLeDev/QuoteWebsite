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

# routes_account.py (remplace _send_reset_email)
from email.message import EmailMessage
from email.utils import formataddr
import smtplib, os, html as pyhtml
from typing import Any

def _get_attr(obj: Any, name: str, default=None):
    # supporte dict et objet ORM
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)

def _send_reset_email(user, link: str, *, dry_run: bool=False) -> bool:
    """
    Envoie un email de réinitialisation. Retourne True si envoyé, False sinon.
    - lit la config SMTP dans data.json (conf["smtp"]) ou variables d'env
    - si dry_run=True : n'envoie pas, affiche ce qui partirait
    """
    # lecture conf
    try:
        from storage import read_db, get_conf
        conf = (get_conf(read_db()) or {})
        smtp = (conf.get("smtp") or {})
        site_name = (conf.get("site_name") or "PastelNotes")
    except Exception:
        smtp, site_name = {}, "PastelNotes"

    host      = smtp.get("host")      or os.getenv("SMTP_HOST")
    port      = int(smtp.get("port") or os.getenv("SMTP_PORT") or 587)
    username  = smtp.get("username")  or os.getenv("SMTP_USERNAME")
    password  = smtp.get("password")  or os.getenv("SMTP_PASSWORD")
    use_tls   = bool(smtp.get("use_tls", True if os.getenv("SMTP_USE_TLS") is None else os.getenv("SMTP_USE_TLS") == "1"))
    use_ssl   = bool(smtp.get("use_ssl", os.getenv("SMTP_USE_SSL") == "1"))
    from_addr = smtp.get("from_addr") or os.getenv("SMTP_FROM_ADDR") or (username or "")
    from_name = smtp.get("from_name") or os.getenv("SMTP_FROM_NAME") or site_name

    to_addr   = _get_attr(user, "email") or _get_attr(user, "mail") or None
    username_safe = _get_attr(user, "username") or _get_attr(user, "name") or "?"

    # compose
    subj = f"[{site_name}] Réinitialisation de votre mot de passe"
    safe_user = pyhtml.escape(username_safe or "")
    text_body = (
        f"Bonjour {safe_user or ''},\n\n"
        f"Vous avez demandé la réinitialisation de votre mot de passe sur {site_name}.\n"
        f"Cliquez sur le lien ci-dessous (valide 2 heures) :\n\n{link}\n\n"
        "Si vous n'êtes pas à l'origine de cette demande, ignorez cet email."
    )
    html_body = (
        f"<p>Bonjour {safe_user or ''},</p>"
        f"<p>Vous avez demandé la réinitialisation de votre mot de passe sur <strong>{pyhtml.escape(site_name)}</strong>.</p>"
        f"<p><a href=\"{pyhtml.escape(link)}\" style=\"display:inline-block;padding:10px 14px;border-radius:6px;"
        f"background:#2d8aa8;color:#fff;text-decoration:none\" target=\"_blank\">Réinitialiser mon mot de passe</a></p>"
        f"<p>Ou copiez-collez ce lien dans votre navigateur :<br>"
        f"<code style=\"word-break:break-all\">{pyhtml.escape(link)}</code></p>"
        f"<p style=\"color:#6b7280;font-size:12px\">Ce lien est valable 2 heures.</p>"
    )

    # validations
    if not to_addr or not host or not from_addr:
        print(f"[reset-mail] SKIP (to={to_addr!r}, host={host!r}, from={from_addr!r}) → lien: {link}")
        return False

    # message
    msg = EmailMessage()
    msg["Subject"] = subj
    msg["From"] = formataddr((from_name, from_addr))
    msg["To"] = to_addr
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")

    # dry run
    if dry_run:
        print("[reset-mail][DRY] from:", msg["From"])
        print("[reset-mail][DRY] to:  ", msg["To"])
        print("[reset-mail][DRY] host:", host, "port:", port, "tls:", use_tls, "ssl:", use_ssl)
        print("[reset-mail][DRY] subj:", subj)
        print("[reset-mail][DRY] link:", link)
        return True

    # send
    try:
        if use_ssl:
            with smtplib.SMTP_SSL(host, port, timeout=20) as c:
                if username and password: c.login(username, password)
                c.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=20) as c:
                c.ehlo()
                if use_tls:
                    c.starttls(); c.ehlo()
                if username and password: c.login(username, password)
                c.send_message(msg)
        print("[reset-mail] sent →", to_addr)
        return True
    except Exception as e:
        try:
            from flask import current_app
            current_app.logger.exception("SMTP send error: %s", e)
        except Exception:
            pass
        print("[reset-mail] ERROR:", e, "| link:", link)
        return False

