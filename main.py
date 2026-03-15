from fastapi import FastAPI, HTTPException, Query, Depends, Header
from pydantic import BaseModel
from typing import Optional, Literal
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
import hashlib
import jwt
from config import get_settings
from database import get_db, engine
from models import Base, User, Advertisement

app = FastAPI()
settings = get_settings()


def on_startup():
    """Создание таблиц при старте приложения."""
    Base.metadata.create_all(bind=engine)


app.add_event_handler("startup", on_startup)


def hash_password(password: str) -> str:
    return hashlib.sha256((password + settings.secret_key).encode()).hexdigest()


def create_jwt(user_id: str) -> str:
    """JWT с полем exp, срок жизни 48 часов, алгоритм HS256."""
    payload = {
        "sub": user_id,
        "exp": datetime.utcnow() + timedelta(hours=settings.jwt_expire_hours),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(
        payload,
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )


def get_user_by_token(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
) -> Optional[dict]:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization[7:].strip()
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        user_id = payload.get("sub")
        if not user_id:
            return None
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return None
    return {"id": user.id, "username": user.username, "role": user.role}


# Schemas
class UserCreate(BaseModel):
    username: str
    password: str
    role: Literal["user", "admin"] = "user"


class UserUpdate(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    role: Optional[Literal["user", "admin"]] = None


class LoginBody(BaseModel):
    username: str
    password: str


class AdvertisementCreate(BaseModel):
    title: str
    description: str
    price: float
    author: str


class AdvertisementUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None
    author: Optional[str] = None


# Login
@app.post("/login")
def login(body: LoginBody, db: Session = Depends(get_db)):
    pwd_hash = hash_password(body.password)
    user = db.query(User).filter(
        User.username == body.username,
        User.password_hash == pwd_hash,
    ).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid login or password")
    return {"token": create_jwt(user.id)}


# User routes
@app.get("/user")
def list_users(
    current: Optional[dict] = Depends(get_user_by_token),
    db: Session = Depends(get_db),
):
    if current is None:
        raise HTTPException(status_code=403, detail="Unauthorized")
    if current["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    users_list = db.query(User).all()
    return [{"id": u.id, "username": u.username, "role": u.role} for u in users_list]


@app.get("/user/{user_id}")
def get_user(
    user_id: str,
    current: Optional[dict] = Depends(get_user_by_token),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Not found")
    return {"id": user.id, "username": user.username, "role": user.role}


@app.post("/user", status_code=201)
def create_user(body: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(status_code=400, detail="Username exists")
    user = User(
        username=body.username,
        password_hash=hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"id": user.id, "username": user.username, "role": user.role}


@app.patch("/user/{user_id}")
def update_user(
    user_id: str,
    body: UserUpdate,
    current: Optional[dict] = Depends(get_user_by_token),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Not found")
    if current is None:
        raise HTTPException(status_code=403, detail="Unauthorized")
    if current["role"] != "admin" and current["id"] != user_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    if body.role is not None and current["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    if body.username is not None:
        user.username = body.username
    if body.password is not None:
        user.password_hash = hash_password(body.password)
    if body.role is not None and current["role"] == "admin":
        user.role = body.role
    db.commit()
    db.refresh(user)
    return {"id": user.id, "username": user.username, "role": user.role}


@app.delete("/user/{user_id}", status_code=204)
def delete_user(
    user_id: str,
    current: Optional[dict] = Depends(get_user_by_token),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Not found")
    if current is None:
        raise HTTPException(status_code=403, detail="Unauthorized")
    if current["role"] != "admin" and current["id"] != user_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    db.delete(user)
    db.commit()
    return None


def ad_to_response(ad: Advertisement) -> dict:
    return {
        "id": ad.id,
        "title": ad.title,
        "description": ad.description,
        "price": ad.price,
        "author": ad.author,
        "created_at": ad.created_at.isoformat() + "Z" if ad.created_at else None,
        "owner_id": ad.owner_id,
    }


# Advertisement routes
@app.post("/advertisement", status_code=201)
def create_advertisement(
    body: AdvertisementCreate,
    current: Optional[dict] = Depends(get_user_by_token),
    db: Session = Depends(get_db),
):
    if current is None:
        raise HTTPException(status_code=403, detail="Unauthorized")
    ad = Advertisement(
        title=body.title,
        description=body.description,
        price=body.price,
        author=body.author,
        owner_id=current["id"],
    )
    db.add(ad)
    db.commit()
    db.refresh(ad)
    return ad_to_response(ad)


@app.get("/advertisement/{advertisement_id}")
def get_advertisement(
    advertisement_id: str,
    db: Session = Depends(get_db),
):
    ad = db.query(Advertisement).filter(Advertisement.id == advertisement_id).first()
    if not ad:
        raise HTTPException(status_code=404, detail="Not found")
    return ad_to_response(ad)


@app.patch("/advertisement/{advertisement_id}")
def update_advertisement(
    advertisement_id: str,
    body: AdvertisementUpdate,
    current: Optional[dict] = Depends(get_user_by_token),
    db: Session = Depends(get_db),
):
    ad = db.query(Advertisement).filter(Advertisement.id == advertisement_id).first()
    if not ad:
        raise HTTPException(status_code=404, detail="Not found")
    if current is None:
        raise HTTPException(status_code=403, detail="Unauthorized")
    if current["role"] != "admin" and ad.owner_id != current["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    if body.title is not None:
        ad.title = body.title
    if body.description is not None:
        ad.description = body.description
    if body.price is not None:
        ad.price = body.price
    if body.author is not None:
        ad.author = body.author
    db.commit()
    db.refresh(ad)
    return ad_to_response(ad)


@app.delete("/advertisement/{advertisement_id}", status_code=204)
def delete_advertisement(
    advertisement_id: str,
    current: Optional[dict] = Depends(get_user_by_token),
    db: Session = Depends(get_db),
):
    ad = db.query(Advertisement).filter(Advertisement.id == advertisement_id).first()
    if not ad:
        raise HTTPException(status_code=404, detail="Not found")
    if current is None:
        raise HTTPException(status_code=403, detail="Unauthorized")
    if current["role"] != "admin" and ad.owner_id != current["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    db.delete(ad)
    db.commit()
    return None


@app.get("/advertisement")
def search_advertisements(
    title: Optional[str] = Query(None),
    description: Optional[str] = Query(None),
    price: Optional[float] = Query(None),
    author: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(Advertisement)
    if title:
        q = q.filter(Advertisement.title.contains(title))
    if description:
        q = q.filter(Advertisement.description.contains(description))
    if price is not None:
        q = q.filter(Advertisement.price == price)
    if author:
        q = q.filter(Advertisement.author == author)
    ads_list = q.all()
    return [ad_to_response(ad) for ad in ads_list]
