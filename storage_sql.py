from __future__ import annotations
import os
from typing import Optional, List, Dict, Any
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from sqlalchemy import String, Text as SAText, Boolean, DateTime, ForeignKey, Table, select
from werkzeug.security import generate_password_hash, check_password_hash

from storage import get_conf, read_db  # on garde la config JSON

# ---------- SQLAlchemy setup ----------
class Base(DeclarativeBase):
    pass

def _db_url() -> str:
    conf = get_conf(read_db())
    url = (conf.get("database") or {}).get("url")
    # Par défaut: ./data/pastelnotes.db
    if not url:
        os.makedirs(os.path.join(os.getcwd(), "data"), exist_ok=True)
        url = "sqlite:///./data/pastelnotes.db"
    # si sqlite relative, créer le dossier ciblé si besoin
    if url.startswith("sqlite:///"):
        path = url.replace("sqlite:///", "")
        d = os.path.dirname(path)
        if d and not os.path.isabs(d):
            d = os.path.join(os.getcwd(), d)
        if d:
            os.makedirs(d, exist_ok=True)
    return url

engine = sa.create_engine(_db_url(), future=True, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, future=True, expire_on_commit=False)

# ---------- Models ----------
text_access = Table(
    "text_access", Base.metadata,
    sa.Column("text_id", sa.Integer, sa.ForeignKey("texts.id", ondelete="CASCADE"), primary_key=True),
    sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
)

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(150), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Nouveau
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    encrypted_user_key: Mapped[Optional[str]] = mapped_column(SAText, nullable=True)

    texts_created = relationship("Text", back_populates="created_by_user")
    texts_allowed = relationship("Text", secondary=text_access, back_populates="allowed_users")

class Text(Base):
    __tablename__ = "texts"
    id: Mapped[int] = mapped_column(primary_key=True)

    # (legacy) champs clairs — on les laisse nullable pour migration, on évite de les remplir en v2
    title: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    body: Mapped[Optional[str]] = mapped_column(SAText, nullable=True)
    context: Mapped[Optional[str]] = mapped_column(SAText, nullable=True)

    # méta non sensibles
    music_url: Mapped[Optional[str]] = mapped_column(String(512))
    music_original_url: Mapped[Optional[str]] = mapped_column(String(512))
    image_filename: Mapped[Optional[str]] = mapped_column(String(512))
    image_url: Mapped[Optional[str]] = mapped_column(String(512))
    image_original_url: Mapped[Optional[str]] = mapped_column(String(512))

    # dates
    date: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # auteur
    created_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_by_user = relationship("User", back_populates="texts_created")

    # permissions
    allowed_users = relationship("User", secondary=text_access, back_populates="texts_allowed")

    # chiffrement v2
    default_allow: Mapped[bool] = mapped_column(Boolean, default=False)
    cipher_alg:    Mapped[Optional[str]] = mapped_column(String(64))
    ciphertext:    Mapped[Optional[str]] = mapped_column(SAText)
    cipher_nonce:  Mapped[Optional[str]] = mapped_column(String(24))

class SpotifyToken(Base):
    __tablename__ = "spotify_tokens"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    access_token: Mapped[Optional[str]] = mapped_column(SAText)
    refresh_token: Mapped[Optional[str]] = mapped_column(SAText)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

class FriendRequest(Base):
    __tablename__ = "friend_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    from_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    to_user_id:   Mapped[int] = mapped_column(ForeignKey("users.id"))
    status:       Mapped[str] = mapped_column(String(16), default="pending")  # 'pending','accepted','declined','cancelled'
    created_at:   Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    responded_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

class Friend(Base):
    __tablename__ = "friends"
    user_id:        Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    friend_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    created_at:     Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# --- helpers d'accès amis -----------------------------------------------------
def _get_user_by_name(s, username: str):
    return s.scalar(select(User).where(sa.func.lower(User.username) == username.strip().lower()))

def are_friends(s, uid1: int, uid2: int) -> bool:
    """
    True si une relation d'amitié existe dans un sens ou dans l'autre.
    (on accepte 1 seule ligne, pas besoin d'avoir la paire)
    """
    FriendTbl = globals().get("Friend")
    FriendReq = globals().get("FriendRequest")
    if FriendTbl:
        a = s.scalar(select(FriendTbl).where(FriendTbl.user_id == uid1, FriendTbl.friend_user_id == uid2))
        b = s.scalar(select(FriendTbl).where(FriendTbl.user_id == uid2, FriendTbl.friend_user_id == uid1))
        if a or b:
            return True
    if FriendReq:
        ar = s.scalar(select(FriendReq).where(FriendReq.from_user_id == uid1, FriendReq.to_user_id == uid2, FriendReq.status == "accepted"))
        br = s.scalar(select(FriendReq).where(FriendReq.from_user_id == uid2, FriendReq.to_user_id == uid1, FriendReq.status == "accepted"))
        if ar or br:
            return True
    return False

def can_user_view_text(username: str, text_id: int) -> bool:
    """Auteur OU explicitement autorisé OU (default_allow & amis)."""
    with SessionLocal() as s:
        u = _get_user_by_name(s, username)
        if not u:
            return False
        t = s.get(Text, text_id)
        if not t:
            return False
        if t.created_by_id == u.id:
            return True
        # autorisé explicitement ?
        seen = s.execute(sa.select(text_access.c.text_id)
                         .where(text_access.c.text_id == text_id,
                                text_access.c.user_id == u.id)).first()
        if seen:
            return True
        # public (amis)
        if t.default_allow and are_friends(s, u.id, t.created_by_id):
            return True
        return False

def list_texts_accessible(username: str) -> list[dict]:
    """Textes créés par l’utilisateur + textes explicitement partagés + textes amis ‘public’."""
    with SessionLocal() as s:
        u = _get_user_by_name(s, username)
        if not u: return []
        # 1) mes textes
        own_q = select(Text).where(Text.created_by_id==u.id)
        own = s.scalars(own_q).all()
        # 2) explicitement partagés
        shared_q = select(Text).join(text_access, text_access.c.text_id==Text.id)\
                               .where(text_access.c.user_id==u.id)
        shared = s.scalars(shared_q).all()
        # 3) amis ‘public’

        friends_ids = select(Friend.friend_user_id).where(Friend.user_id==u.id)
        public_q = select(Text).where(Text.created_by_id.in_(friends_ids),
                                      Text.default_allow.is_(True))
        public = s.scalars(public_q).all()

        rows = {t.id: t for t in (own + shared + public)}.values()
        out=[]
        for t in rows:
            out.append({
                "id": t.id,
                "title": t.title,
                "body": t.body,
                "context": t.context,
                "music_url": t.music_url,
                "music_original_url": t.music_original_url,
                "image_filename": t.image_filename,
                "image_url": t.image_url,
                "date_dt": t.date,
                "date": t.date.isoformat() if t.date else None,
                "created_by": t.created_by_user.username,
                "allowed_usernames": [uu.username for uu in t.allowed_users],
                "default_allow": bool(t.default_allow),
            })
        return out


def init_db() -> None:
    Base.metadata.create_all(bind=engine)

    with engine.begin() as conn:
        conn.exec_driver_sql("""
        CREATE TABLE IF NOT EXISTS password_resets (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          token TEXT NOT NULL UNIQUE,
          expires_at TEXT NOT NULL,
          used INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)
        conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS idx_password_resets_user_id ON password_resets(user_id);")
        conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token);")

# ---------- Helpers (users) ----------
def _pepper() -> str:
    return (get_conf(read_db()).get("password_pepper") or "")

def get_user(username: str) -> Optional[Dict[str, Any]]:
    with SessionLocal() as s:
        u = s.scalar(select(User).where(sa.func.lower(User.username) == username.strip().lower()))
        if not u:
            return None
        return {"username": u.username, "is_admin": u.is_admin, "created_at": u.created_at.isoformat(), "email": u.email}

def list_users() -> List[Dict[str, Any]]:
    with SessionLocal() as s:
        rows = s.scalars(select(User).order_by(User.is_admin.desc(), User.username.asc())).all()
        return [{"username": u.username, "is_admin": u.is_admin, "created_at": u.created_at.isoformat()} for u in rows]

def add_user(username: str, password: str, is_admin: bool=False) -> None:
    with SessionLocal.begin() as s:
        if s.scalar(select(User).where(sa.func.lower(User.username) == username.strip().lower())):
            raise ValueError("username already exists")
        u = User(username=username.strip(),
                 password_hash=generate_password_hash(password + _pepper()),
                 is_admin=is_admin)
        s.add(u)

def set_user_password(username: str, password: str) -> None:
    with SessionLocal.begin() as s:
        u = s.scalar(select(User).where(sa.func.lower(User.username) == username.strip().lower()))
        if not u:
            raise ValueError("user not found")
        u.password_hash = generate_password_hash(password + _pepper())

def check_user_password(username: str, password: str) -> bool:
    with SessionLocal() as s:
        u = s.scalar(select(User).where(sa.func.lower(User.username) == username.strip().lower()))
        return bool(u and check_password_hash(u.password_hash, password + _pepper()))

def admin_username() -> str:
    return (get_conf(read_db()).get("admin") or {}).get("username", "admin")

def check_admin_password(username: str, password: str) -> bool:
    if username.strip().lower() != admin_username().lower():
        return False
    return check_user_password(username, password)

# ---------- Helpers (texts) ----------
def list_texts_for_user(username: str, is_admin: bool) -> List[Dict[str, Any]]:
    with SessionLocal() as s:
        if is_admin:
            rows = s.scalars(select(Text).order_by(Text.date.desc())).all()
        else:
            u = s.scalar(select(User).where(sa.func.lower(User.username) == username.strip().lower()))
            if not u: return []
            own = list(s.scalars(select(Text).where(Text.created_by_id == u.id)).all())
            shared = list(u.texts_allowed)
            rows = {t.id: t for t in own + shared}.values()  # dédoublonne
            rows = sorted(rows, key=lambda t: t.date, reverse=True)
        out = []
        for t in rows:
            # On ne renvoie pas le plaintext; on inclut seulement méta + auteur
            out.append({
                "id": t.id,
                "date_dt": t.date,
                "date": t.date.isoformat(),
                "created_by": t.created_by_user.username,
                "allowed_usernames": [u.username for u in t.allowed_users],
                # Legacy support (si des textes anciens ont encore title):
                "title": t.title,
                "image_filename": t.image_filename,
                "image_url": t.image_url,
                "music_url": t.music_url,
            })
        return out

def get_text_dict(text_id: int) -> Optional[Dict[str, Any]]:
    with SessionLocal() as s:
        t = s.get(Text, text_id)
        if not t:
            return None
        return {
            "id": t.id,
            "date": t.date.isoformat(),
            "created_at": t.created_at.isoformat(),
            "updated_at": t.updated_at.isoformat(),
            "created_by": t.created_by_user.username,

            # champs chiffrés
            "cipher_alg": t.cipher_alg,
            "ciphertext": t.ciphertext,
            "cipher_nonce": t.cipher_nonce,

            # méta non sensibles
            "music_url": t.music_url,
            "music_original_url": t.music_original_url,
            "image_filename": t.image_filename,
            "image_url": t.image_url,
            "image_original_url": t.image_original_url,

            # permissions
            "allowed_usernames": [u.username for u in t.allowed_users],

            # legacy (pour compat si nécessaire)
            "title": t.title,
            "body": t.body,
            "context": t.context,
            "default_allow": t.default_allow,
        }

def create_text(created_by_username: str, data: Dict[str, Any], allowed_usernames: List[str]) -> int:
    """
    data attend au minimum:
      - cipher_alg, ciphertext, cipher_nonce
      - date_dt (datetime) optionnel
      - default_allow (bool) optionnel
      - meta: music_url, music_original_url, image_filename, image_url, image_original_url
    """
    with SessionLocal.begin() as s:
        owner = s.scalar(select(User).where(sa.func.lower(User.username) == created_by_username.strip().lower()))
        if not owner:
            raise ValueError("creator not found")
        t = Text(
            # ⚠️ legacy: on remplit un vide pour respecter NOT NULL existant
            title=None, body="", context=None,

            # chiffrement v2
            cipher_alg=data.get("cipher_alg"),
            ciphertext=data.get("ciphertext"),
            cipher_nonce=data.get("cipher_nonce"),
            default_allow=bool(data.get("default_allow") or False),

            # méta
            music_url=data.get("music_url"),
            music_original_url=data.get("music_original_url"),
            image_filename=data.get("image_filename"),
            image_url=data.get("image_url"),
            image_original_url=data.get("image_original_url"),

            date=data.get("date_dt") or datetime.utcnow(),
            created_by_user=owner,
        )
        s.add(t);
        s.flush()  # <<< ajoute/flush avant d'attacher les permissions
        if allowed_usernames:
            allow = s.scalars(select(User).where(sa.func.lower(User.username)
                                                 .in_([u.strip().lower() for u in allowed_usernames]))).all()
            t.allowed_users = list(allow)
        s.add(t)
        s.flush()
        return t.id

def update_text(text_id: int, data: Dict[str, Any], allowed_usernames: List[str] | None) -> None:
    with SessionLocal.begin() as s:
        t = s.get(Text, text_id)
        if not t:
            raise ValueError("text not found")

        # MAJ champs chiffrés / flag
        for k in ["cipher_alg", "ciphertext", "cipher_nonce", "default_allow"]:
            if k in data:
                setattr(t, k, data.get(k))

        # MAJ méta
        for k in ["music_url", "music_original_url", "image_filename", "image_url", "image_original_url"]:
            if k in data:
                setattr(t, k, data.get(k))

        # date si fournie
        if "date_dt" in data and data["date_dt"]:
            t.date = data["date_dt"]

        # permissions si demande explicite
        if allowed_usernames is not None:
            allow = s.scalars(
                select(User).where(sa.func.lower(User.username).in_([u.strip().lower() for u in allowed_usernames]))
            ).all()
            t.allowed_users = list(allow)

def delete_text(text_id: int) -> bool:
    with SessionLocal.begin() as s:
        t = s.get(Text, text_id)
        if not t:
            return False
        s.delete(t)
        return True

# ---------- Migration depuis JSON (legacy) ----------
def _parse_dt(v) -> Optional[datetime]:
    if not v:
        return None
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00").replace(" ", "T"))
    except Exception:
        return None

def migrate_json_to_sql() -> Dict[str, int]:
    """
    Lit data.json et insère users/texts si absents.
    - Dates parsées en datetime.
    - Les anciens champs clairs sont copiés (pour compat), mais V2 n'en crée plus de nouveaux.
    """
    from storage import read_db as _read
    db = _read()
    added_u = added_t = 0
    with SessionLocal.begin() as s:
        # users
        for u in db.get("users", []):
            uname = (u.get("username") or "").strip()
            if not uname:
                continue
            existing = s.scalar(select(User).where(sa.func.lower(User.username) == uname.lower()))
            if existing:
                continue
            nu = User(username=uname,
                      password_hash=u.get("password_hash") or "",
                      is_admin=bool(u.get("is_admin")))
            s.add(nu)
            added_u += 1
        # ensure admin
        adm = (db.get("config", {}).get("admin", {}) or {}).get("username") or "admin"
        adm_u = s.scalar(select(User).where(sa.func.lower(User.username) == adm.lower()))
        if not adm_u:
            s.add(User(username=adm, password_hash="", is_admin=True))
            added_u += 1
        s.flush()

        # texts (legacy clair -> vers colonnes legacy ; les nouveaux iront en chiffré)
        for t in db.get("texts", []):
            title = t.get("title")
            body = (t.get("body") or "")
            dt = _parse_dt(t.get("date")) or datetime.utcnow()
            creator_name = t.get("created_by")
            creator = s.scalar(select(User).where(User.username == creator_name))
            if not creator:
                continue

            q = select(Text.id).where(Text.created_by_id == creator.id, Text.date == dt)
            if title is None:
                q = q.where(Text.title.is_(None))
            else:
                q = q.where(Text.title == title)
            exists_id = s.scalar(q.limit(1))
            if exists_id:
                continue

            nt = Text(
                title=title, body=str(body), context=t.get("context"),
                music_url=t.get("music_url"), music_original_url=t.get("music_original_url"),
                image_filename=t.get("image_filename"), image_url=t.get("image_url"),
                image_original_url=t.get("image_original_url"),
                date=dt,
                created_at=_parse_dt(t.get("created_at")) or datetime.utcnow(),
                updated_at=datetime.utcnow(),
                created_by_user=creator
            )
            allow = [u for u in (t.get("allowed_usernames") or []) if u]
            if allow:
                allow_rows = s.scalars(select(User).where(sa.func.lower(User.username).in_([x.lower() for x in allow]))).all()
                nt.allowed_users = list(allow_rows)
            s.add(nt)
            added_t += 1
    return {"users_added": added_u, "texts_added": added_t}

def list_friendship(username:str) -> Dict[str, list]:
    with SessionLocal() as s:
        u = _get_user_by_name(s, username);
        if not u:
            return {"accepted":[], "pending_out":[], "pending_in":[]}
        # accepted
        rows = s.scalars(select(Friend).where(Friend.user_id==u.id)).all()
        accepted = []
        for f in rows:
            fri = s.get(User, f.friend_user_id)
            if fri: accepted.append(fri.username)
        # pending out / in
        po = s.scalars(select(FriendRequest).where(FriendRequest.from_user_id==u.id, FriendRequest.status=="pending")).all()
        pending_out = [s.get(User, r.to_user_id).username for r in po if s.get(User, r.to_user_id)]
        pi = s.scalars(select(FriendRequest).where(FriendRequest.to_user_id==u.id, FriendRequest.status=="pending")).all()
        pending_in = [s.get(User, r.from_user_id).username for r in pi if s.get(User, r.from_user_id)]
        return {"accepted":accepted, "pending_out":pending_out, "pending_in":pending_in}

def send_friend_request(from_username:str, to_username:str) -> None:
    if from_username.strip().lower() == to_username.strip().lower():
        raise ValueError("Impossible de s'ajouter soi-même.")
    with SessionLocal.begin() as s:
        a = _get_user_by_name(s, from_username); b = _get_user_by_name(s, to_username)
        if not a or not b: raise ValueError("Utilisateur introuvable.")
        # déjà amis ?
        if s.get(Friend, {"user_id":a.id,"friend_user_id":b.id}):
            return
        # pending existant ?
        exists = s.scalar(select(FriendRequest).where(FriendRequest.from_user_id==a.id,
                                                     FriendRequest.to_user_id==b.id,
                                                     FriendRequest.status=="pending"))
        if exists: return
        # s'il y a une demande inverse en pending, on accepte directement
        inverse = s.scalar(select(FriendRequest).where(FriendRequest.from_user_id==b.id,
                                                       FriendRequest.to_user_id==a.id,
                                                       FriendRequest.status=="pending"))
        if inverse:
            inverse.status="accepted"; inverse.responded_at=datetime.utcnow()
            _add_mutual_friendship(s, a, b)
            _propagate_default_allow(s, author=a, new_friend=b)
            _propagate_default_allow(s, author=b, new_friend=a)
            return
        fr = FriendRequest(from_user_id=a.id, to_user_id=b.id, status="pending")
        s.add(fr)

def cancel_friend_request(from_username:str, to_username:str) -> None:
    with SessionLocal.begin() as s:
        a = _get_user_by_name(s, from_username); b = _get_user_by_name(s, to_username)
        if not a or not b: return
        fr = s.scalar(select(FriendRequest).where(FriendRequest.from_user_id==a.id,
                                                  FriendRequest.to_user_id==b.id,
                                                  FriendRequest.status=="pending"))
        if fr:
            fr.status = "cancelled"; fr.responded_at = datetime.utcnow()

def _add_mutual_friendship(s, a:User, b:User):
    if not s.get(Friend, {"user_id":a.id,"friend_user_id":b.id}):
        s.add(Friend(user_id=a.id, friend_user_id=b.id))
    if not s.get(Friend, {"user_id":b.id,"friend_user_id":a.id}):
        s.add(Friend(user_id=b.id, friend_user_id=a.id))

def _propagate_default_allow(s, author:User, new_friend:User):
    ids = [t.id for t in s.scalars(select(Text).where(Text.created_by_id==author.id, Text.default_allow==True)).all()]
    for tid in ids:
        exists = s.execute(sa.select(text_access.c.text_id)
                           .where(text_access.c.text_id==tid, text_access.c.user_id==new_friend.id)).first()
        if not exists:
            s.execute(sa.insert(text_access).values(text_id=tid, user_id=new_friend.id))

def respond_friend_request(me_username:str, other_username:str, accept:bool) -> None:
    with SessionLocal.begin() as s:
        me    = _get_user_by_name(s, me_username)
        other = _get_user_by_name(s, other_username)
        if not me or not other: raise ValueError("Utilisateur introuvable.")
        fr = s.scalar(select(FriendRequest).where(FriendRequest.to_user_id==me.id,
                                                  FriendRequest.from_user_id==other.id,
                                                  FriendRequest.status=="pending"))
        if not fr: return
        fr.status      = "accepted" if accept else "declined"
        fr.responded_at = datetime.utcnow()
        if accept:
            _add_mutual_friendship(s, me, other)
            _propagate_default_allow(s, author=other, new_friend=me)
            _propagate_default_allow(s, author=me,    new_friend=other)

def remove_friend(me_username:str, other_username:str) -> None:
    with SessionLocal.begin() as s:
        me    = _get_user_by_name(s, me_username)
        other = _get_user_by_name(s, other_username)
        if not me or not other: return
        s.execute(sa.delete(Friend).where(Friend.user_id==me.id, Friend.friend_user_id==other.id))
        s.execute(sa.delete(Friend).where(Friend.user_id==other.id, Friend.friend_user_id==me.id))

def list_texts_visible_to(viewer_username: str, author_username: str) -> List[Text]:
    """
    Textes de 'author' visibles par 'viewer':
    - si viewer == author -> tous
    - sinon: explicitement partagés OU (default_allow & amis)
    """
    with SessionLocal() as s:
        viewer = _get_user_by_name(s, viewer_username)
        author = _get_user_by_name(s, author_username)
        if not viewer or not author:
            return []

        rows = s.scalars(select(Text).where(Text.created_by_id == author.id)
                         .order_by(Text.date.desc())).all()
        out = []
        for t in rows:
            if t.created_by_id == viewer.id:
                out.append(t); continue
            # partage explicite
            seen = s.execute(sa.select(text_access.c.text_id)
                             .where(text_access.c.text_id == t.id,
                                    text_access.c.user_id == viewer.id)).first()
            if seen:
                out.append(t); continue
            # public (amis)
            if t.default_allow and are_friends(s, viewer.id, author.id):
                out.append(t)
        return out



# --- Access helpers ----------------------------------------------------------
def all_usernames(exclude: list[str] | None = None) -> list[str]:
    """Liste de tous les usernames (sans admin par défaut, et sans doublons)."""
    ex = {x.strip().lower() for x in (exclude or [])}
    with SessionLocal() as s:
        q = select(User.username)
        rows = s.execute(q).scalars().all()
        return [u for u in rows if u.strip().lower() not in ex]


# Exports utiles à d'autres modules
__all__ = [
    "sa", "select", "SessionLocal", "init_db",
    "User", "Text", "SpotifyToken", "text_access",
    "get_user", "list_users", "add_user", "set_user_password",
    "check_user_password", "admin_username", "check_admin_password",
    "list_texts_for_user", "get_text_dict", "create_text", "update_text", "delete_text",
    "Friend","FriendRequest",
    "list_friendship","send_friend_request","cancel_friend_request","respond_friend_request","remove_friend",
    "list_texts_visible_to",
]
