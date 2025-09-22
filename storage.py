from __future__ import annotations

import base64
import json
import os
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, List

from werkzeug.security import generate_password_hash, check_password_hash

from paths import DATA_PATH

# ---------------- Default DB ----------------

DEFAULT_DB: Dict[str, Any] = {
    "config": {
        "site_name": "Pastel Notes",
        "secret_key": secrets.token_hex(32),
        "password_pepper": "",
        "admin": {"username": "admin", "password_hash": None},
        "spotify": {
            "client_id": "",
            "client_secret": "",
            "redirect_uri": "http://localhost:5000/spotify/callback",
        },
    },
    "oauth": {
        "spotify_tokens": {},  # { "<username_lower>": {access_token, refresh_token, expires_at ISO} }
        "spotify_app": {  # { access_token, expires_at (epoch seconds) }
        },
    },
    "users": [],  # {username, password_hash, created_at}
    "texts": [],  # see routes_texts.py
    "next_ids": {"text": 1},
    "limits": { "max_request_mb": 1024, "import_max_mb": 512, "upload_max_mb": 256 }
}


# --------------- FS helpers ---------------

def _atomic_write(path, data: Dict[str, Any]) -> None:
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def read_db() -> Dict[str, Any]:
    if not DATA_PATH.exists():
        _atomic_write(DATA_PATH, DEFAULT_DB)
        return json.loads(json.dumps(DEFAULT_DB))
    with DATA_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_db(db: Dict[str, Any]) -> None:
    _atomic_write(DATA_PATH, db)


# --------------- Config helpers ---------------

def get_conf(db: Dict[str, Any]) -> Dict[str, Any]:
    out = json.loads(json.dumps(DEFAULT_DB["config"]))
    out.update(db.get("config", {}))
    if "admin" not in out:
        out["admin"] = {"username": "admin", "password_hash": None}
    return out


def set_conf_key(db: Dict[str, Any], dotted_key: str, value: Any) -> None:
    keys = dotted_key.split(".")
    node = db.setdefault("config", {})
    for k in keys[:-1]:
        node = node.setdefault(k, {})
    node[keys[-1]] = value


def next_id(db: Dict[str, Any], kind: str) -> int:
    nid = int(db.setdefault("next_ids", {}).setdefault(kind, 1))
    db["next_ids"][kind] = nid + 1
    return nid


# --------------- Users & Admin ---------------

def pepper(db: Dict[str, Any]) -> str:
    return get_conf(db).get("password_pepper", "")


def _canon_username(u: str) -> str:
    return (u or "").strip().lower()


def list_users(db: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(db.get("users", []))


def get_user(db: Dict[str, Any], username: str) -> Optional[Dict[str, Any]]:
    key = _canon_username(username)
    for u in db.get("users", []):
        if _canon_username(u.get("username")) == key:
            return u
    return None


def add_user(db: Dict[str, Any], username: str, password: str) -> Dict[str, Any]:
    if get_user(db, username):
        raise ValueError("username already exists")
    u = {
        "username": username.strip(),
        "password_hash": generate_password_hash(password + pepper(db)),
        "created_at": datetime.utcnow().isoformat(),
    }
    db.setdefault("users", []).append(u)
    return u


def set_user_password(db: Dict[str, Any], username: str, password: str) -> None:
    u = get_user(db, username)
    if not u:
        raise ValueError("user not found")
    u["password_hash"] = generate_password_hash(password + pepper(db))


def check_user_password(db: Dict[str, Any], username: str, password: str) -> bool:
    u = get_user(db, username)
    return bool(u and check_password_hash(u["password_hash"], password + pepper(db)))


def ensure_unique_usernames(db: Dict[str, Any]) -> None:
    users = db.get("users", [])
    if not users:
        return
    last_index_by_key = {}
    for i, u in enumerate(users):
        k = _canon_username(u.get("username"))
        if k:
            last_index_by_key[k] = i  # conserve la dernière occurrence
    deduped = [users[i] for i in sorted(last_index_by_key.values())]
    db["users"] = deduped


# --- Admin helpers (sync avec users[]) ---
def _admin_conf(db: Dict[str, Any]) -> Dict[str, Any]:
    return db.setdefault("config", {}).setdefault("admin", {})


def set_admin_password(db: Dict[str, Any], password: str) -> None:
    conf = _admin_conf(db)
    conf["password_hash"] = generate_password_hash(password + pepper(db))
    sync_admin_user(db)


def set_admin_username(db: Dict[str, Any], new_username: str) -> None:
    conf = _admin_conf(db)
    old_username = conf.get("username") or "admin"
    new_username = new_username.strip()
    conf["username"] = new_username

    old_user = get_user(db, old_username)
    new_user = get_user(db, new_username)
    if old_user and not new_user:
        old_user["username"] = new_username
    elif old_user and new_user and old_user is not new_user:
        db["users"].remove(old_user)

    sync_admin_user(db)


def sync_admin_user(db: Dict[str, Any]) -> None:
    conf = get_conf(db)
    admin_username = (conf.get("admin", {}) or {}).get("username")
    admin_ph = (conf.get("admin", {}) or {}).get("password_hash")
    if not admin_username:
        return
    u = get_user(db, admin_username)
    if u:
        if admin_ph:
            u["password_hash"] = admin_ph
    else:
        if admin_ph:
            db.setdefault("users", []).append({
                "username": admin_username,
                "password_hash": admin_ph,
                "created_at": datetime.utcnow().isoformat(),
            })
    ensure_unique_usernames(db)
    u2 = get_user(db, admin_username)
    if u2 and admin_ph:
        u2["password_hash"] = admin_ph


def check_admin_password(db: Dict[str, Any], username: str, password: str) -> bool:
    conf = get_conf(db)
    if username.strip().lower() != conf["admin"]["username"].lower():
        return False
    ph = conf["admin"].get("password_hash")
    return bool(ph and check_password_hash(ph, password + pepper(db)))


# --------------- Spotify helpers ---------------

def get_spotify_conf(db: Dict[str, Any]) -> Dict[str, Any]:
    return (get_conf(db).get("spotify") or {})


def _tok_store(db: Dict[str, Any]) -> Dict[str, Any]:
    return db.setdefault("oauth", {}).setdefault("spotify_tokens", {})


def get_spotify_token_record(db: Dict[str, Any], username: str):
    return _tok_store(db).get(_canon_username(username))


def set_spotify_token_record(db: Dict[str, Any], username: str, access_token: str, refresh_token: str, expires_in: int):
    rec = {
        "access_token": access_token,
        "refresh_token": refresh_token or "",
        "expires_at": (datetime.utcnow() + timedelta(seconds=max(0, int(expires_in) - 60))).isoformat()
    }
    _tok_store(db)[_canon_username(username)] = rec
    return rec


def refresh_spotify_token(db: Dict[str, Any], username: str) -> dict | None:
    rec = get_spotify_token_record(db, username)
    conf = get_spotify_conf(db)
    if not (rec and rec.get("refresh_token") and conf.get("client_id") and conf.get("client_secret")):
        return None
    try:
        if datetime.utcnow() < datetime.fromisoformat(rec["expires_at"]):
            return rec
    except Exception:
        pass
    auth = base64.b64encode(f"{conf['client_id']}:{conf['client_secret']}".encode()).decode()
    import requests
    resp = requests.post(
        "https://accounts.spotify.com/api/token",
        data={"grant_type": "refresh_token", "refresh_token": rec["refresh_token"]},
        headers={"Authorization": f"Basic {auth}"},
        timeout=15,
    )
    if resp.status_code != 200:
        return None
    data = resp.json()
    access = data["access_token"]
    new_refresh = rec["refresh_token"] if "refresh_token" not in data else data["refresh_token"]
    expires_in = data.get("expires_in", 3600)
    return set_spotify_token_record(db, username, access, new_refresh, expires_in)


def get_spotify_app_token(db: Dict[str, Any]) -> str | None:
    """Token 'client credentials' pour meta/preview (pas d'utilisateur)."""
    store = db.setdefault("oauth", {}).setdefault("spotify_app", {})
    exp = store.get("expires_at")
    import time, requests
    if store.get("access_token") and isinstance(exp, (int, float)) and exp > time.time():
        return store["access_token"]
    conf = get_spotify_conf(db)
    if not (conf.get("client_id") and conf.get("client_secret")):
        return None
    auth = base64.b64encode(f"{conf['client_id']}:{conf['client_secret']}".encode()).decode()
    r = requests.post(
        "https://accounts.spotify.com/api/token",
        data={"grant_type": "client_credentials"},
        headers={"Authorization": f"Basic {auth}"},
        timeout=15,
    )
    if r.status_code != 200:
        return None
    j = r.json()
    store["access_token"] = j["access_token"]
    store["expires_at"] = time.time() + int(j.get("expires_in", 3600)) - 60
    return store["access_token"]
