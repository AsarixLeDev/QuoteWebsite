from __future__ import annotations
import re
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, login_required, current_user
import storage_sql as store
from auth import LoginUser
import crypto_server as cserv  # pour UDK à la création

auth_account_bp = Blueprint("auth_account", __name__)

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,30}$")

def _valid_username(u: str) -> bool:
    return bool(_USERNAME_RE.match(u.strip()))

def _valid_password(p: str) -> bool:
    return len(p or "") >= 8

@auth_account_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email    = (request.form.get("email") or "").strip() or None
        password = request.form.get("password") or ""
        confirm  = request.form.get("confirm") or ""

        if not _valid_username(username):
            flash("Nom d'utilisateur invalide (3-30 caractères, a-z, 0-9, _.-).")
            return render_template("register.html")

        if password != confirm or not _valid_password(password):
            flash("Mot de passe invalide (8+ caractères) ou confirmation différente.")
            return render_template("register.html", username=username, email=email or "")

        # existe déjà ?
        if store.get_user(username):
            flash("Ce nom d'utilisateur existe déjà.")
            return render_template("register.html", username=username, email=email or "")

        # crée l'utilisateur (non-admin)
        store.add_user(username, password, is_admin=False)

        # (optionnel) stocker l'email si tu veux le garder
        if email:
            with store.SessionLocal.begin() as s:
                u = s.scalar(store.select(store.User).where(store.sa.func.lower(store.User.username)==username.lower()))
                if u:
                    u.email = email

        # clé UDK pour chiffrement côté serveur
        try:
            cserv.ensure_user_udk(username)
        except Exception:
            pass  # en dernier recours, le texte sera refusé si pas d'UDK

        # auto-login
        login_user(LoginUser(username, False))
        flash("Bienvenue sur PastelNotes !")
        return redirect(url_for("core.dashboard"))

    return render_template("register.html")

@auth_account_bp.route("/me/password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current = request.form.get("current") or ""
        new     = request.form.get("new") or ""
        confirm = request.form.get("confirm") or ""

        if not store.check_user_password(current_user.get_id(), current):
            flash("Mot de passe actuel incorrect.")
            return render_template("me_password.html")

        if new != confirm or not _valid_password(new):
            flash("Le nouveau mot de passe est invalide (8+ caractères) ou confirmation différente.")
            return render_template("me_password.html")

        store.set_user_password(current_user.get_id(), new)
        flash("Mot de passe mis à jour.")
        return redirect(url_for("core.dashboard"))

    return render_template("me_password.html")
