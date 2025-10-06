from __future__ import annotations

import argparse
import json
import os
import storage_sql

from flask import Flask

import jobs
from config import ensure_admin_seed, get_conf, set_conf_key
from paths import BASE_DIR
# Blueprints
from routes_core import core_bp
from routes_texts import texts_bp
from storage import (
    read_db, write_db,
    get_user, list_users, add_user, set_user_password,
    set_admin_username, set_admin_password,
)
from werkzeug.exceptions import RequestEntityTooLarge


try:
    # Spotify est optionnel mais recommandé
    from routes_spotify import spotify_bp
except Exception as _e:
    spotify_bp = None
    print("[WARN] routes_spotify non importé :", _e)


def create_app() -> Flask:
    """Crée et configure l'application Flask."""
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
        static_url_path="/static",
    )
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    storage_sql.init_db()

    from storage import get_conf
    limits = (get_conf(read_db()).get("limits") or {})
    app.config['MAX_CONTENT_LENGTH'] = int(limits.get("max_request_mb", 1024)) * 1024 * 1024

    # Config depuis data.json
    db = read_db()
    conf = get_conf(db)
    app.config.update(
        SECRET_KEY=conf.get("secret_key"),
        SEND_FILE_MAX_AGE_DEFAULT=0,  # utile en dev pour le cache
    )

    # Sanity check CSS
    css_path = os.path.join(app.static_folder, "styles.css")
    if not os.path.isfile(css_path):
        print(f"[WARN] styles.css introuvable : {css_path}")

    def _handle_413(e):
        from flask import request, redirect, url_for, flash
        cap = app.config.get('MAX_CONTENT_LENGTH') or 0
        mb = int(cap / (1024 * 1024)) if cap else '?'
        flash(f"Fichier trop volumineux (> {mb} Mo).")
        if request.path.startswith('/admin/import'):
            return redirect(url_for('core.admin_import')), 303
        return redirect(url_for('core.dashboard')), 303

    app.register_error_handler(RequestEntityTooLarge, _handle_413)

    # Auth
    from auth import init_login
    init_login(app)

    # Blueprints
    app.register_blueprint(core_bp)
    app.register_blueprint(texts_bp)
    if spotify_bp:
        app.register_blueprint(spotify_bp)
    jobs.init_app(app)
    return app


def cli_main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Pastel Notes — Flask + JSON + Admin unique")
    sub = parser.add_subparsers(dest="cmd")

    # run
    p_run = sub.add_parser("run", help="Lancer le serveur web")
    p_run.add_argument("--host", default="127.0.0.1")
    p_run.add_argument("--port", type=int, default=5000)
    p_run.add_argument("--debug", action="store_true")

    # config
    sub.add_parser("config-show", help="Afficher la configuration")
    p_set = sub.add_parser("config-set",
                           help="Modifier une clef (ex: site_name, password_pepper, secret_key, spotify.client_id)")
    p_set.add_argument("key")
    p_set.add_argument("value")

    # users (console uniquement)
    p_uc = sub.add_parser("users-create", help="Créer un utilisateur (non-admin)")
    p_uc.add_argument("--username", required=True)
    p_uc.add_argument("--password", required=True)

    p_up = sub.add_parser("users-set-password", help="Changer le mot de passe d’un utilisateur (non-admin)")
    p_up.add_argument("--username", required=True)
    p_up.add_argument("--password", required=True)

    sub.add_parser("users-list", help="Lister les utilisateurs")

    # admin unique
    p_admu = sub.add_parser("admin-set-username", help="Changer le username admin (synchronise son user)")
    p_admu.add_argument("--username", required=True)

    p_admp = sub.add_parser("admin-set-password", help="Changer le mot de passe admin (synchronise son user)")
    p_admp.add_argument("--password", required=True)

    # utilitaire de test d'auth
    p_auth = sub.add_parser("auth-test", help="Tester un couple (username/password)")
    p_auth.add_argument("--username", required=True)
    p_auth.add_argument("--password", required=True)

    p_dbinit = sub.add_parser("db-init", help="Créer les tables SQL (si absentes)")
    p_dbmig = sub.add_parser("migrate-json-to-sql", help="Importer data.json vers la base SQL")

    args = parser.parse_args(argv)

    # run server
    if not args.cmd or args.cmd == "run":
        ensure_admin_seed()
        app = create_app()
        app.run(
            host=getattr(args, "host", "127.0.0.1"),
            port=getattr(args, "port", 5000),
            debug=getattr(args, "debug", False),
        )
        return

    # autres commandes CLI
    if args.cmd == "config-show":
        conf = get_conf(read_db())
        print(json.dumps(conf, ensure_ascii=False, indent=2))
        return

    if args.cmd == "config-set":
        db = read_db()
        set_conf_key(db, args.key, args.value)
        write_db(db)
        if args.key == "secret_key":
            print("Attention: SECRET_KEY changé → déconnexion des sessions actives.")
        print(f"OK: {args.key} = {args.value}")
        return

    if args.cmd == "users-create":
        db = read_db()
        if get_user(db, args.username):
            print("Erreur: ce username existe déjà.")
            return
        try:
            add_user(db, args.username, args.password)
        except ValueError as e:
            print(f"Erreur: {e}")
            return
        write_db(db)
        print(f"Utilisateur créé: {args.username}")
        return

    if args.cmd == "users-set-password":
        db = read_db()
        if not get_user(db, args.username):
            print("Erreur: utilisateur introuvable.")
            return
        set_user_password(db, args.username, args.password)
        write_db(db)
        print("Mot de passe mis à jour.")
        return

    if args.cmd == "users-list":
        db = read_db()
        for u in list_users(db):
            print(f"- {u['username']}")
        return

    if args.cmd == "admin-set-username":
        db = read_db()
        set_admin_username(db, args.username)
        write_db(db)
        print(f"Admin username = {args.username} (user synchronisé)")
        return

    if args.cmd == "admin-set-password":
        db = read_db()
        set_admin_password(db, args.password)
        write_db(db)
        print("Mot de passe admin mis à jour (user synchronisé).")
        return

    if args.cmd == "auth-test":
        from storage import check_admin_password, check_user_password
        db = read_db()
        ok = check_admin_password(db, args.username, args.password) or check_user_password(db, args.username,
                                                                                           args.password)
        print("OK" if ok else "FAIL")
        return

    if args.cmd == "db-init":
        storage_sql.init_db()
        print("OK: tables créées (si besoin).");
        return

    if args.cmd == "migrate-json-to-sql":
        storage_sql.init_db()
        r = storage_sql.migrate_json_to_sql()
        print(f"Migration: {r}");
        return


if __name__ == "__main__":
    cli_main()
