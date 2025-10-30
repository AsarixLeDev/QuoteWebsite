from __future__ import annotations
import storage_sql as store
from storage_sql import get_user  # or your existing helper
import base64, os, json
from typing import Optional, Dict, Any, List
from datetime import datetime

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from storage import read_db, get_conf
from storage_sql import SessionLocal, select, User, update_text, sa
import base64, os, json, re
from typing import Optional, Dict, Any, List
from datetime import datetime

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from storage import read_db, get_conf
from storage_sql import SessionLocal, select, User, update_text, sa


# ---------------- config helpers ----------------
def _conf() -> Dict[str, Any]:
    try:
        return get_conf(read_db()) or {}
    except Exception:
        return {}

def _master_key_path() -> str:
    c = _conf().get("crypto") or {}
    p = c.get("master_key_path")
    if not p or not os.path.isfile(p):
        raise RuntimeError("config.crypto.master_key_path introuvable")
    return p

def _smk_file_first32(path: str) -> bytes:
    raw = open(path, "rb").read()
    if len(raw) < 32:
        raise RuntimeError(f"SMK trop courte: {path}")
    return raw[:32]

def _smk_paths() -> List[str]:
    paths = []
    try:
        paths.append(_master_key_path())
    except Exception:
        pass
    legacy = (_conf().get("crypto_legacy") or {})
    for p in (legacy.get("smk_paths") or []):
        if p and os.path.isfile(p) and p not in paths:
            paths.append(p)
    return paths

def _master_key_bytes() -> bytes:
    return _smk_file_first32(_master_key_path())


# ---------------- robust base64 ----------------
_B64JUNK = re.compile(r"[^A-Za-z0-9+/_=\\-]")     # allow urlsafe too

def _b64d_any(s: str) -> bytes:
    """
    Robust base64: strip whitespace, drop junk, add '=' padding, try std then urlsafe.
    """
    if s is None:
        raise ValueError("empty base64")
    if not isinstance(s, str):
        s = str(s)
    x = s.strip().replace(" ", "").replace("\n", "").replace("\r", "")
    x = _B64JUNK.sub("", x)
    # try std
    for dec in (base64.b64decode, base64.urlsafe_b64decode):
        t = x
        # add padding to multiple of 4
        pad = (-len(t)) % 4
        if pad:
            t += "=" * pad
        try:
            return dec(t)
        except Exception:
            continue
    # last try: treat original input as already-bytes?
    return base64.b64decode(x + "="*((-len(x))%4))


# ---------------- new scheme (AES-GCM with master) ----------------
def _aesgcm_decrypt_with_key(key: bytes, nonce_b64: str, ct_b64: str) -> Dict[str, Any]:
    nonce = _b64d_any(nonce_b64) if nonce_b64 else b""
    ct = _b64d_any(ct_b64)
    # IMPORTANT: old code used aad=None, keep it identical
    clear = AESGCM(key).decrypt(nonce, ct, None)
    return json.loads(clear.decode("utf-8", "replace"))

def _aesgcm_encrypt_with_key(key: bytes, clear_dict: Dict[str, Any]) -> Dict[str, str]:
    data = json.dumps(clear_dict, ensure_ascii=False).encode("utf-8")
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, data, None)  # aad=None (compat)
    return {
        "cipher_alg": "AES-GCM-256-v1",
        "ciphertext": base64.b64encode(ct).decode("ascii"),
        "cipher_nonce": base64.b64encode(nonce).decode("ascii"),
    }


# ---------------- legacy scheme (your pasted code) ----------------
def _fernet_from_smk_user(smk: bytes, username: str) -> Fernet:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),     # identical to your old snippet
        length=32,
        salt=b"pastelnotes/fernet",
        info=(b"user:" + username.encode("utf-8")),
    )
    key = hkdf.derive(smk)  # 32B
    return Fernet(base64.urlsafe_b64encode(key))

def _load_user_udk_via_smk(username: str, smk: bytes) -> Optional[bytes]:
    with SessionLocal() as s:
        u = s.scalar(select(User).where(sa.func.lower(User.username) == username.lower()))
        if not u or not u.encrypted_user_key:
            return None
        f = _fernet_from_smk_user(smk, u.username)
        try:
            udk = f.decrypt(u.encrypted_user_key.encode("utf-8"))
            return udk if len(udk) == 32 else None
        except Exception:
            return None

def _legacy_decrypt_with_any_smk(username: str, nonce_b64: str, ct_b64: str) -> Optional[Dict[str, Any]]:
    nonce = _b64d_any(nonce_b64) if nonce_b64 else b""
    ct = _b64d_any(ct_b64)
    for path in _smk_paths():
        try:
            smk = _smk_file_first32(path)
        except Exception:
            continue
        udk = _load_user_udk_via_smk(username, smk)
        if not udk:
            continue
        try:
            clear = AESGCM(udk).decrypt(nonce, ct, None)  # aad=None (compat)
            return json.loads(clear.decode("utf-8","replace"))
        except Exception:
            continue
    return None


# ---------------- compat API for routes ----------------
def compat_decrypt_and_rewrap_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    row: { id, created_by, cipher_alg, ciphertext, cipher_nonce }
    Try master AES-GCM first (new rows), then legacy UDK derivation per user.
    If legacy succeeds and auto_rewrap, replace row ciphertext with master-encrypted payload.
    """
    author = row.get("created_by") or ""
    ct_b64 = row.get("ciphertext") or ""
    n_b64  = row.get("cipher_nonce") or ""

    # 1) new
    try:
        return _aesgcm_decrypt_with_key(_master_key_bytes(), n_b64, ct_b64)
    except Exception:
        pass

    # 2) legacy
    clear = _legacy_decrypt_with_any_smk(author, n_b64, ct_b64)
    if clear is None:
        raise ValueError(f"Compat decrypt failed for row id={row.get('id')} author={author}")

    # optional rewrap
    auto = bool((_conf().get("crypto_legacy") or {}).get("auto_rewrap", True))
    if auto and row.get("id") is not None:
        try:
            payload = _aesgcm_encrypt_with_key(_master_key_bytes(), clear)
            update_text(row["id"], {
                "cipher_alg":  payload["cipher_alg"],
                "ciphertext":  payload["ciphertext"],
                "cipher_nonce": payload["cipher_nonce"],
                "updated_at": datetime.utcnow().isoformat()
            }, allowed_usernames=None)
        except Exception:
            pass

    return clear


def _read_key_file(path: str) -> Optional[bytes]:
    """Return 32 raw bytes. Accepts raw 32B or base64 text files."""
    try:
        raw = open(path, "rb").read().strip()
        # raw bytes?
        if len(raw) == 32:
            return raw
        # maybe base64?
        try:
            b = base64.b64decode(raw)
            if len(b) == 32:
                return b
        except Exception:
            pass
        # maybe text file containing a b64 string
        try:
            s = open(path, "r", encoding="utf-8").read().strip()
            b = base64.b64decode(s)
            if len(b) == 32:
                return b
        except Exception:
            pass
    except Exception:
        pass
    return None

def _keyring_global() -> List[bytes]:
    """Master first, then legacy files from config.crypto_legacy.files_global."""
    out: List[bytes] = []
    mk = _master_key_bytes()
    out.append(mk)
    legacy = (_conf().get("crypto_legacy") or {})
    files = legacy.get("files_global") or []
    for path in files:
        b = _read_key_file(path)
        if b and b not in out:
            out.append(b)
    return out


def _legacy_algs() -> List[str]:
    legacy = (_conf().get("crypto_legacy") or {})
    return list(legacy.get("algs") or ["aesgcm"])


def encrypt_text_payload(clear: Dict[str, str]) -> Dict[str, str]:
    """
    Encrypt a clear dict {'title','body','context'} with the CURRENT master (AES-GCM).
    Returns {'cipher_alg','ciphertext','cipher_nonce'} (base64 strings).
    """
    payload = json.dumps(clear, ensure_ascii=False).encode("utf-8")
    key = _master_key_bytes()
    aes = AESGCM(key)
    # 12-byte nonce for AES-GCM
    import os
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, payload, b"")
    return {
        "cipher_alg": "AES-GCM-256-v1",
        "ciphertext": base64.b64encode(ct).decode("ascii"),
        "cipher_nonce": base64.b64encode(nonce).decode("ascii"),
    }


def decrypt_text_payload(ciphertext_b64: str, nonce_b64: str, alg_hint: Optional[str] = None) -> Dict[str, str]:
    """
    Try CURRENT master, then legacy keys (global) with AES-GCM (or other algs if listed).
    Returns a clear dict.
    DOES NOT rewrap or update the DB (use decrypt_and_rewrap_row for that).
    """
    ct = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64) if nonce_b64 else b""
    tried_algs = [alg_hint] if alg_hint else _legacy_algs()
    keys = _keyring_global()
    last_err: Optional[Exception] = None

    for alg in tried_algs:
        if (alg or "").lower().startswith("aes"):
            for i, key in enumerate(keys):
                try:
                    clear = AESGCM(key).decrypt(nonce, ct, b"")
                    return json.loads(clear.decode("utf-8", "replace"))
                except Exception as e:
                    last_err = e
                    continue
        else:
            # only AES-GCM is expected; extend here if you truly need Fernet etc.
            continue
    raise last_err or ValueError("decryption failed")


def decrypt_and_rewrap_row(text_row: Dict[str, Any]) -> Dict[str, str]:
    """
    Try to decrypt a DB row {'created_by','ciphertext','cipher_nonce',...}.
    If a LEGACY key was used and auto_rewrap=true -> re-encrypt to master and update row.
    """
    legacy = (_conf().get("crypto_legacy") or {})
    auto = bool(legacy.get("auto_rewrap", True))

    ct_b64 = text_row.get("ciphertext") or ""
    n_b64  = text_row.get("cipher_nonce") or ""
    alg    = (text_row.get("cipher_alg") or "AES-GCM-256-v1")

    # try master first (index 0)
    keys = _keyring_global()
    if not keys:
        raise RuntimeError("no keys configured")

    ct = base64.b64decode(ct_b64)
    nonce = base64.b64decode(n_b64) if n_b64 else b""

    # master first
    try:
        clear_json = AESGCM(keys[0]).decrypt(nonce, ct, b"")
        return json.loads(clear_json.decode("utf-8","replace"))
    except Exception:
        pass

    # then legacy
    for i in range(1, len(keys)):
        try:
            clear_json = AESGCM(keys[i]).decrypt(nonce, ct, b"")
            data = json.loads(clear_json.decode("utf-8","replace"))

            # rewrap to master?
            if auto and text_row.get("id") is not None:
                try:
                    payload = encrypt_text_payload(data)
                    update_text(text_row["id"], {
                        "cipher_alg":  payload["cipher_alg"],
                        "ciphertext":  payload["ciphertext"],
                        "cipher_nonce": payload["cipher_nonce"],
                        "updated_at": datetime.utcnow().isoformat()
                    }, allowed_usernames=None)
                except Exception:
                    # non-fatal; the read already succeeded
                    pass
            return data
        except Exception:
            continue

    raise ValueError("decryption failed with master and legacy keys")

def _b64key_to_bytes(b64s: str) -> Optional[bytes]:
    try:
        return base64.b64decode(b64s)
    except Exception:
        return None

def _primary_key_b64(username: str) -> Optional[str]:
    u = get_user(username)
    # adapt attr names to your model
    return getattr(u, "encryption_key_b64", None) or getattr(u, "encryption_key", None)

def _user_primary_key_b64(username: str) -> Optional[str]:
    """
    Return the current PRIMARY key for a user (the one you already use today).
    You likely store it on the User row (e.g. user.encryption_key_b64 or similar).
    Adjust to your actual storage accessor.
    """
    u = get_user(username)
    # adapt the attribute name to your model (encrypted or already-decoded)
    k = getattr(u, "encryption_key_b64", None) or getattr(u, "encryption_key", None)
    return k

def legacy_alg_list() -> List[str]:
    legacy = (_conf().get("crypto_legacy") or {})
    return list(legacy.get("algs") or ["xchacha20poly1305", "aesgcm", "fernet"])

def user_keyring_bytes(username: str) -> List[bytes]:
    """
    Key order: PRIMARY first, then per-user legacy files, then global legacy files.
    Returns a de-duplicated list of 32-byte secrets.
    """
    out: List[bytes] = []
    p_b64 = _primary_key_b64(username)
    if p_b64:
        try:
            kb = base64.b64decode(p_b64.strip())
            if len(kb) == 32:
                out.append(kb)
        except Exception:
            pass

    legacy = (_conf().get("crypto_legacy") or {})
    per_user = (legacy.get("files_per_user") or {}).get(username) or []
    glob = (legacy.get("files_global") or [])

    for path in per_user + glob:
        kb = _read_key_file(path)
        if kb and kb not in out:
            out.append(kb)
    return out

def _alg_list() -> List[str]:
    return list((_conf().get("crypto_legacy_algs") or ["xchacha20poly1305"]))

def _load_smk() -> bytes:
    path = (get_conf(read_db()).get("crypto") or {}).get("master_key_path")
    if not path or not os.path.exists(path):
        raise RuntimeError("config.crypto.master_key_path introuvable")
    raw = open(path, "rb").read()
    if len(raw) < 32:
        raise RuntimeError("SMK trop courte")
    return raw[:32]

def _fernet_from_smk(smk: bytes, context: bytes) -> Fernet:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),          #  <-- () important
        length=32,
        salt=b"pastelnotes/fernet",
        info=context,
    )
    key = hkdf.derive(smk)
    return Fernet(base64.urlsafe_b64encode(key))

def ensure_user_udk(username: str) -> None:
    """Génère l'UDK d'un user si absente (scellée avec SMK)."""
    smk = _load_smk()
    with store.SessionLocal.begin() as s:
        u = s.scalar(store.select(store.User).where(store.sa.func.lower(store.User.username)==username.lower()))
        if not u:
            raise ValueError("user not found")
        if not u.encrypted_user_key:
            udk = os.urandom(32)
            f = _fernet_from_smk(smk, b"user:"+u.username.encode())
            u.encrypted_user_key = f.encrypt(udk).decode()

def ensure_all_user_udk() -> int:
    """Initialise UDK pour tous les users manquants."""
    smk = _load_smk()
    n = 0
    with store.SessionLocal.begin() as s:
        users = s.scalars(store.select(store.User)).all()
        for u in users:
            if not u.encrypted_user_key:
                udk = os.urandom(32)
                f = _fernet_from_smk(smk, b"user:"+u.username.encode())
                u.encrypted_user_key = f.encrypt(udk).decode()
                n += 1
    return n

def _user_udk(author_username: str) -> bytes:
    smk = _load_smk()
    with store.SessionLocal() as s:
        u = s.scalar(store.select(store.User).where(store.sa.func.lower(store.User.username)==author_username.lower()))
        if not u or not u.encrypted_user_key:
            raise RuntimeError("UDK absente pour "+author_username)
        f = _fernet_from_smk(smk, b"user:"+u.username.encode())
        return f.decrypt(u.encrypted_user_key.encode())

def rewrap_to_primary(username: str, clear: Dict[str, str], *, text_id: Optional[int] = None):
    """
    Re-encrypt the given clear payload with the PRIMARY key.
    If text_id is provided, update the row (cipher_alg, ciphertext, cipher_nonce).
    """
    payload = encrypt_text_payload(username, clear)
    if text_id is None:
        return payload
    from storage_sql import update_text
    update_text(text_id, {
        "cipher_alg":  payload.get("cipher_alg"),
        "ciphertext":  payload.get("ciphertext"),
        "cipher_nonce": payload.get("cipher_nonce"),
        "updated_at": datetime.utcnow().isoformat()
    })