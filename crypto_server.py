from __future__ import annotations
import base64, json, os
from typing import Dict, Any
from datetime import datetime
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from storage import read_db, get_conf
import storage_sql as store

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

def encrypt_text_payload(author_username: str, payload: Dict[str, Any]) -> Dict[str, str]:
    key = _user_udk(author_username)
    data = json.dumps(payload, ensure_ascii=False).encode()
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, data, None)
    return {"ciphertext": base64.b64encode(ct).decode(),
            "cipher_nonce": base64.b64encode(iv).decode(),
            "cipher_alg": "AES-GCM-256-v1"}

def decrypt_text_payload(author_username: str, ciphertext: str, nonce: str) -> Dict[str, Any]:
    key = _user_udk(author_username)
    ct = base64.b64decode(ciphertext); iv = base64.b64decode(nonce)
    data = AESGCM(key).decrypt(iv, ct, None)
    return json.loads(data.decode())