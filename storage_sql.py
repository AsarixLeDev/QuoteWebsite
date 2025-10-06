from __future__ import annotations
import os
from typing import Optional, List, Dict, Any
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import sqlalchemy as sa
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from sqlalchemy import String, Text as SAText, Boolean, DateTime, ForeignKey, Table, select

from storage import get_conf, read_db  # on garde la config JSON

# ---------- SQLAlchemy setup ----------
class Base(DeclarativeBase): pass

def _db_url() -> str:
    conf = get_conf(read_db())
    url = (conf.get("database") or {}).get("url")
    # Par défaut: ./data/pastelnotes.db
    if not url:
        # s'assurer que ./data existe
        os.makedirs(os.path.join(os.getcwd(), "data"), exist_ok=True)
        url = "sqlite:///./data/pastelnotes.db"
    # si sqlite relative, créer le dossier ciblé si besoin
    if url.startswith("sqlite:///"):
        path = url.replace("sqlite:///", "")
        d = os.path.dirname(path)
        if d and not os.path.isabs(d):
            d = os.path.join(os.getcwd(), d)
        if d: os.makedirs(d, exist_ok=True)
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

    texts_created = relationship("Text", back_populates="created_by_user")
    texts_allowed = relationship("Text", secondary=text_access, back_populates="allowed_users")

class Text(Base):
    __tablename__ = "texts"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[Optional[str]] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(SAText)
    context: Mapped[Optional[str]] = mapped_column(SAText)
    music_url: Mapped[Optional[str]] = mapped_column(String(512))
    music_original_url: Mapped[Optional[str]] = mapped_column(String(512))
    image_filename: Mapped[Optional[str]] = mapped_column(String(512))
    image_url: Mapped[Optional[str]] = mapped_column(String(512))
    image_original_url: Mapped[Optional[str]] = mapped_column(String(512))
    date: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    created_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_by_user = relationship("User", back_populates="texts_created")

    allowed_users = relationship("User", secondary=text_access, back_populates="texts_allowed")

class SpotifyToken(Base):
    __tablename__ = "spotify_tokens"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    access_token: Mapped[Optional[str]] = mapped_column(SAText)
    refresh_token: Mapped[Optional[str]] = mapped_column(SAText)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

def init_db() -> None:
    Base.metadata.create_all(bind=engine)

# ---------- Helpers ----------
def _pepper() -> str: return (get_conf(read_db()).get("password_pepper") or "")

def get_user(username: str) -> Optional[Dict[str, Any]]:
    with SessionLocal() as s:
        u = s.scalar(select(User).where(sa.func.lower(User.username)==username.strip().lower()))
        if not u: return None
        return {"username": u.username, "is_admin": u.is_admin, "created_at": u.created_at.isoformat()}

def list_users() -> List[Dict[str, Any]]:
    with SessionLocal() as s:
        rows = s.scalars(select(User).order_by(User.is_admin.desc(), User.username.asc())).all()
        return [{"username": u.username, "is_admin": u.is_admin, "created_at": u.created_at.isoformat()} for u in rows]

def add_user(username: str, password: str, is_admin: bool=False) -> None:
    with SessionLocal.begin() as s:
        if s.scalar(select(User).where(sa.func.lower(User.username)==username.strip().lower())):
            raise ValueError("username already exists")
        u = User(username=username.strip(), password_hash=generate_password_hash(password+_pepper()), is_admin=is_admin)
        s.add(u)

def set_user_password(username: str, password: str) -> None:
    with SessionLocal.begin() as s:
        u = s.scalar(select(User).where(sa.func.lower(User.username)==username.strip().lower()))
        if not u: raise ValueError("user not found")
        u.password_hash = generate_password_hash(password+_pepper())

def check_user_password(username: str, password: str) -> bool:
    with SessionLocal() as s:
        u = s.scalar(select(User).where(sa.func.lower(User.username)==username.strip().lower()))
        return bool(u and check_password_hash(u.password_hash, password+_pepper()))

def admin_username() -> str:
    return (get_conf(read_db()).get("admin") or {}).get("username","admin")

def check_admin_password(username: str, password: str) -> bool:
    if username.strip().lower() != admin_username().lower():
        return False
    return check_user_password(username, password)

# --- Texts ---
def list_texts_for_user(username: str, is_admin: bool) -> List[Dict[str, Any]]:
    with SessionLocal() as s:
        if is_admin:
            rows = s.scalars(select(Text).order_by(Text.date.desc())).all()
        else:
            u = s.scalar(select(User).where(sa.func.lower(User.username)==username.strip().lower()))
            if not u: return []
            rows = list(u.texts_allowed)
            rows.sort(key=lambda t: t.date, reverse=True)
        out=[]
        for t in rows:
            out.append({
                "id": t.id, "title": t.title, "body": t.body, "context": t.context,
                "music_url": t.music_url, "image_filename": t.image_filename, "image_url": t.image_url,
                "date_dt": t.date, "date": t.date.isoformat(),
                "created_by": t.created_by_user.username,
                "allowed_usernames": [u.username for u in t.allowed_users],
            })
        return out

def get_text_dict(text_id: int) -> Optional[Dict[str, Any]]:
    with SessionLocal() as s:
        t = s.get(Text, text_id)
        if not t: return None
        return {
            "id": t.id, "title": t.title, "body": t.body, "context": t.context,
            "music_url": t.music_url, "music_original_url": t.music_original_url,
            "image_filename": t.image_filename, "image_url": t.image_url,
            "image_original_url": t.image_original_url,
            "date": t.date.isoformat(), "created_at": t.created_at.isoformat(), "updated_at": t.updated_at.isoformat(),
            "created_by": t.created_by_user.username,
            "allowed_usernames": [u.username for u in t.allowed_users],
        }

def create_text(created_by_username: str, data: Dict[str, Any], allowed_usernames: List[str]) -> int:
    with SessionLocal.begin() as s:
        owner = s.scalar(select(User).where(sa.func.lower(User.username)==created_by_username.strip().lower()))
        if not owner: raise ValueError("creator not found")
        t = Text(
            title=data.get("title"),
            body=str(data.get("body") or ""),               # toujours string
            context=data.get("context"),
            music_url=data.get("music_url"),
            music_original_url=data.get("music_original_url"),
            image_filename=data.get("image_filename"),
            image_url=data.get("image_url"),
            image_original_url=data.get("image_original_url"),
            date=data.get("date_dt") or datetime.utcnow(),
            created_by_user=owner,
        )
        if allowed_usernames:
            allow = s.scalars(select(User).where(sa.func.lower(User.username).in_([u.strip().lower() for u in allowed_usernames]))).all()
            t.allowed_users = list(allow)
        s.add(t); s.flush()
        return t.id

def update_text(text_id: int, data: Dict[str, Any], allowed_usernames: List[str] | None) -> None:
    with SessionLocal.begin() as s:
        t = s.get(Text, text_id)
        if not t: raise ValueError("text not found")
        # champs libres
        for k in ["title","context","music_url","music_original_url","image_filename","image_url","image_original_url"]:
            if k in data: setattr(t, k, data.get(k))
        if "body" in data: t.body = str(data.get("body") or "")
        if "date_dt" in data and data["date_dt"]: t.date = data["date_dt"]
        if allowed_usernames is not None:
            allow = s.scalars(select(User).where(sa.func.lower(User.username).in_([u.strip().lower() for u in allowed_usernames]))).all()
            t.allowed_users = list(allow)

# --- Migration depuis JSON ---
def _parse_dt(v) -> Optional[datetime]:
    if not v: return None
    try: return datetime.fromisoformat(v.replace("Z","+00:00").replace(" ","T"))
    except Exception: return None

def migrate_json_to_sql() -> Dict[str,int]:
    """
    Lit data.json et insère users/texts si absents.
    - Dates parsées en datetime.
    - body toujours casté en str pour éviter les objets inattendus.
    """
    from storage import read_db as _read
    db = _read()
    added_u = added_t = 0
    with SessionLocal.begin() as s:
        # users
        for u in db.get("users", []):
            uname = (u.get("username") or "").strip()
            if not uname: continue
            existing = s.scalar(select(User).where(sa.func.lower(User.username)==uname.lower()))
            if existing: continue
            nu = User(username=uname,
                      password_hash=u.get("password_hash") or "",
                      is_admin=bool(u.get("is_admin")))
            s.add(nu); added_u += 1
        # ensure admin
        adm = (db.get("config",{}).get("admin",{}) or {}).get("username") or "admin"
        adm_u = s.scalar(select(User).where(sa.func.lower(User.username)==adm.lower()))
        if not adm_u:
            s.add(User(username=adm, password_hash="", is_admin=True)); added_u += 1
        s.flush()

        # texts
        for t in db.get("texts", []):
            title = t.get("title")
            body  = str(t.get("body") or "")
            dt    = _parse_dt(t.get("date")) or datetime.utcnow()
            creator_name = t.get("created_by")
            creator = s.scalar(select(User).where(User.username==creator_name))
            if not creator: continue

            # existe déjà ? (title/body/date/creator)
            q = select(Text.id).where(Text.body==body, Text.created_by_id==creator.id)
            if title is None:
                q = q.where(Text.title.is_(None))
            else:
                q = q.where(Text.title==title)
            if dt:
                q = q.where(Text.date==dt)
            exists_id = s.scalar(q.limit(1))
            if exists_id:
                continue

            nt = Text(
                title=title, body=body, context=t.get("context"),
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
            s.add(nt); added_t += 1
    return {"users_added": added_u, "texts_added": added_t}
