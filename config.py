from __future__ import annotations

from storage import (
    read_db, write_db, set_admin_password, sync_admin_user, ensure_unique_usernames
)


def ensure_admin_seed() -> None:
    """
    Garantit qu'un admin existe :
    - si pas de password_hash admin, initialise 'change-me-now'
    - synchronise l'entrée users[] correspondante
    - nettoie les doublons de usernames
    """
    db = read_db()
    conf = get_conf(db)
    admin_conf = (conf.get("admin") or {})
    if not admin_conf.get("username"):
        # par prudence, on crée la clef si elle manque
        db.setdefault("config", {}).setdefault("admin", {}).setdefault("username", "admin")

    if not admin_conf.get("password_hash"):
        # seed un mot de passe par défaut (à changer rapidement)
        set_admin_password(db, "change-me-now")  # crée/synchronise aussi le user admin
        write_db(db)
        print("\n--- Admin initialisé ---")
        print(f"Username: {db['config']['admin']['username']}")
        print("Password: change-me-now (à modifier via: python app.py admin-set-password --password NouveauMDP)\n")
    else:
        # assure la cohérence si data.json a été édité à la main
        sync_admin_user(db)
        write_db(db)

    # nettoyage des doublons éventuels
    db = read_db()
    ensure_unique_usernames(db)
    write_db(db)


# Ré-export pratique pour app.py
from storage import get_conf, set_conf_key  # noqa: F401
