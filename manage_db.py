from __future__ import annotations
import argparse, os, json, base64
from datetime import datetime

import storage_sql as store
from storage_sql import SessionLocal, sa, select
from werkzeug.security import generate_password_hash
from storage import read_db, get_conf, write_db
import crypto_server as cserv


# ---------------- Master key ----------------
def ensure_master_key(path: str) -> None:
    path = os.path.abspath(path)
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)
    if not os.path.exists(path):
        # 32 octets aléatoires
        os.urandom(1)  # "warm up"
        key = os.urandom(32)
        with open(path, "wb") as f:
            f.write(key)
        print(f"[mk] Master key créée: {path}")
    else:
        print(f"[mk] Master key déjà présente: {path}")


# ---------------- DB init / reset ----------------
def init_db(reset: bool = False) -> None:
    if reset:
        print("[db] DROP ALL")
        store.Base.metadata.drop_all(bind=store.engine)
    store.Base.metadata.create_all(bind=store.engine)
    print("[db] CREATE ALL OK")


# ---------------- Migration data.json -> SQL ----------------
def _parse_dt(v) -> datetime:
    if not v:
        return datetime.utcnow()
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00").replace(" ", "T"))
    except Exception:
        return datetime.utcnow()


def migrate_json_to_sql(json_path: str = "data.json") -> dict:
    if not os.path.exists(json_path):
        raise FileNotFoundError(json_path)
    dbj = json.loads(open(json_path, "r", encoding="utf-8").read())

    added_users = 0
    set_pwd = 0
    added_texts = 0
    added_access = 0
    added_tokens = 0

    with SessionLocal.begin() as s:
        # ---- Utilisateurs ----
        users = dbj.get("users", [])
        for u in users:
            uname = (u.get("username") or "").strip()
            if not uname:
                continue
            exists = s.scalar(select(store.User).where(sa.func.lower(store.User.username) == uname.lower()))
            if exists:
                continue
            ph = u.get("password_hash")
            row = store.User(
                username=uname,
                password_hash=ph or "",        # on écrase plus bas si vide
                is_admin=bool(u.get("is_admin", False)),
                created_at=_parse_dt(u.get("created_at")),
            )
            s.add(row)
            added_users += 1
        s.flush()

        # Assurer l'admin
        adm = (dbj.get("config", {}).get("admin", {}) or {}).get("username") or "admin"
        admin_row = s.scalar(select(store.User).where(sa.func.lower(store.User.username) == adm.lower()))
        if not admin_row:
            admin_row = store.User(username=adm, password_hash="", is_admin=True, created_at=datetime.utcnow())
            s.add(admin_row)
            added_users += 1
        else:
            if not admin_row.is_admin:
                admin_row.is_admin = True
        s.flush()

    # Définir mot de passe par défaut si manquant (hors transaction pour utiliser helper)
    with SessionLocal() as s:
        rows = s.scalars(select(store.User)).all()
    for u in rows:
        if not u.password_hash:
            store.set_user_password(u.username, "change-me-now")
            set_pwd += 1

    # UDK pour tous
    n_udk = cserv.ensure_all_user_udk()
    print(f"[crypto] UDK initialisées pour {n_udk} utilisateur(s).")

    with SessionLocal.begin() as s:
        # ---- Textes ----
        texts = dbj.get("texts", [])
        for t in texts:
            author_name = (t.get("created_by") or "").strip()
            if not author_name:
                continue
            author = s.scalar(select(store.User).where(store.sa.func.lower(store.User.username) == author_name.lower()))
            if not author:
                # crée l'auteur "fantôme" si nécessaire
                author = store.User(username=author_name, password_hash="", is_admin=False, created_at=datetime.utcnow())
                s.add(author)
                s.flush()
                store.set_user_password(author.username, "change-me-now")

            # déjà importés ? (title/body/date/author) — legacy
            title = t.get("title")
            body  = (t.get("body") or "")
            dt    = _parse_dt(t.get("date"))
            q = select(store.Text.id).where(store.Text.created_by_id == author.id, store.Text.date == dt)
            if title is None:
                q = q.where(store.Text.title.is_(None))
            else:
                q = q.where(store.Text.title == title)
            exists_id = s.scalar(q.limit(1))
            if exists_id:
                continue

            # construire payload clair (legacy); sinon si JSON contient déjà ciphertext, on réutilise
            cipher_alg = t.get("cipher_alg")
            ciphertext = t.get("ciphertext")
            cipher_nonce = t.get("cipher_nonce")
            if not (cipher_alg and ciphertext and cipher_nonce):
                clear = {"title": t.get("title"), "body": t.get("body"), "context": t.get("context")}
                enc = cserv.encrypt_text_payload(author.username, clear)
                cipher_alg   = enc["cipher_alg"]
                ciphertext   = enc["ciphertext"]
                cipher_nonce = enc["cipher_nonce"]

            row = store.Text(
                # legacy clair (on les met vides/nulls)
                title=None,
                body="",
                context=None,
                # crypto
                cipher_alg=cipher_alg,
                ciphertext=ciphertext,
                cipher_nonce=cipher_nonce,
                default_allow=bool(t.get("default_allow") or False),
                # méta non sensibles
                music_url=t.get("music_url"),
                music_original_url=t.get("music_original_url"),
                image_filename=t.get("image_filename"),
                image_url=t.get("image_url"),
                image_original_url=t.get("image_original_url"),
                # dates
                date=dt,
                created_at=_parse_dt(t.get("created_at")),
                updated_at=_parse_dt(t.get("updated_at")),
                # auteur
                created_by_id=author.id,
            )
            s.add(row); s.flush()
            added_texts += 1

            # permissions
            allow = [u for u in (t.get("allowed_usernames") or []) if u]
            if allow:
                for uname in allow:
                    fr = s.scalar(select(store.User).where(store.sa.func.lower(store.User.username) == uname.strip().lower()))
                    if fr:
                        # existe déjà ?
                        seen = s.execute(sa.select(store.text_access.c.text_id)
                                         .where(store.text_access.c.text_id == row.id,
                                                store.text_access.c.user_id == fr.id)).first()
                        if not seen:
                            s.execute(sa.insert(store.text_access).values(text_id=row.id, user_id=fr.id))
                            added_access += 1

        # ---- Spotify tokens (si présents) ----
        tokmap = (dbj.get("oauth", {}) or {}).get("spotify_tokens", {}) or {}
        for uname_lower, rec in tokmap.items():
            # best effort
            u = s.scalar(select(store.User).where(store.sa.func.lower(store.User.username) == uname_lower.strip().lower()))
            if not u:
                continue
            # supprime l'ancien si existant
            old = s.get(store.SpotifyToken, u.id)
            if old:
                s.delete(old)
            s.add(store.SpotifyToken(
                user_id=u.id,
                access_token=rec.get("access_token"),
                refresh_token=rec.get("refresh_token"),
                expires_at=_parse_dt(rec.get("expires_at")),
            ))
            added_tokens += 1

    return {
        "users_added": added_users,
        "users_pwd_set": set_pwd,
        "texts_added": added_texts,
        "text_access_added": added_access,
        "spotify_tokens": added_tokens,
    }


# ---------------- CLI ----------------
def main():
    ap = argparse.ArgumentParser(description="PastelNotes DB setup & migration")
    ap.add_argument("--reset", action="store_true", help="DROP + CREATE ALL (danger)")
    ap.add_argument("--init", action="store_true", help="create tables if not exist")
    ap.add_argument("--migrate", action="store_true", help="migrate data.json -> SQL")
    ap.add_argument("--json", default="data/data.json", help="path to data.json (default: data.json)")
    ap.add_argument("--master-key", default=None, help="path to master key (default: from config.crypto.master_key_path)")
    args = ap.parse_args()

    # master key
    mk_path = args.master_key or (get_conf(read_db()).get("crypto") or {}).get("master_key_path") or "./data/pastelnotes.key"
    ensure_master_key(mk_path)

    # DB init/reset
    if args.reset:
        init_db(reset=True)
    elif args.init:
        init_db(reset=False)

    # Migration
    if args.migrate:
        r = migrate_json_to_sql(args.json)
        print("[migrate] ", r)

    if not (args.init or args.reset or args.migrate):
        ap.print_help()


if __name__ == "__main__":
    main()
