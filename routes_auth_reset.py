# routes_auth_reset.py
from __future__ import annotations
from flask import Blueprint, render_template, request, redirect, url_for, flash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from storage import get_conf, read_db
import storage_sql as store

auth_reset_bp = Blueprint("auth_reset", __name__)

def _serializer():
    # SECRET_KEY vient de ton app; ici on le relit via config JSON pour éviter l'import circulaire
    # si tu préfères, remplace par current_app.config["SECRET_KEY"]
    conf = get_conf(read_db())
    secret = conf.get("secret_key") or "dev-secret"
    return URLSafeTimedSerializer(secret)

@auth_reset_bp.route("/auth/reset", methods=["GET","POST"])
def request_reset():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        if not username:
            flash("Nom d'utilisateur requis."); return render_template("auth_reset_request.html")
        token = _serializer().dumps({"u": username})
        link  = url_for("auth_reset.use_reset", token=token, _external=True)
        # En prod tu peux envoyer un email; en dev on affiche en console
        print("\n=== RESET LINK ===\n", link, "\n==================\n")
        flash("Lien de réinitialisation généré (voir console en dev).")
        return redirect(url_for("core.login"))
    return render_template("auth_reset_request.html")

@auth_reset_bp.route("/auth/reset/<token>", methods=["GET","POST"])
def use_reset(token: str):
    try:
        data = _serializer().loads(token, max_age=3600)
    except SignatureExpired:
        flash("Lien expiré."); return redirect(url_for("auth_reset.request_reset"))
    except BadSignature:
        flash("Lien invalide."); return redirect(url_for("auth_reset.request_reset"))

    username = data.get("u") or ""
    if request.method == "POST":
        pw = request.form.get("password") or ""
        if not pw:
            flash("Mot de passe requis.")
        else:
            store.set_user_password(username, pw)
            flash("Mot de passe mis à jour.")
            return redirect(url_for("core.login"))
    return render_template("auth_reset_form.html", username=username)
