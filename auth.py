from __future__ import annotations

from typing import Optional

from flask import redirect, url_for, flash, request
from flask_login import LoginManager, UserMixin
import storage_sql as store

from storage import read_db, get_conf, get_user

login_manager = LoginManager()
login_manager.login_view = "core.login"  # endpoint de la page login
login_manager.login_message = "Veuillez vous connecter."
login_manager.refresh_view = "core.login"  # en cas de refresh forcé


class LoginUser(UserMixin):
    """Objet utilisateur minimal pour Flask-Login."""

    def __init__(self, username: str, is_admin: bool = False):
        self._id = username
        self.is_admin = bool(is_admin)

    def get_id(self) -> str:
        return self._id


@login_manager.user_loader
def load_user(user_id: str) -> Optional[LoginUser]:
    """
    Recharge l'utilisateur depuis la session. user_id est le username.
    - Admin : défini par la config (stockée côté JSON mais c'est juste un nom).
    - Sinon : on vérifie l'existence via SQL (storage_sql).
    """
    try:
        admin_name = store.admin_username()  # lit la conf JSON via storage_sql
    except Exception:
        admin_name = "admin"

    if user_id and user_id.strip().lower() == admin_name.strip().lower():
        return LoginUser(admin_name, True)

    u = store.get_user(user_id)  # -> dict {'username':..., 'is_admin':..., ...} ou None
    if u:
        return LoginUser(u["username"], False)

    return None


@login_manager.unauthorized_handler
def _unauthorized():
    # redirige vers login avec next=...
    flash("Authentification requise.")
    return redirect(url_for("core.login", next=request.path))


def init_login(app):
    """À appeler dans create_app()."""
    login_manager.init_app(app)
