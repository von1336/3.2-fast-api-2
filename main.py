from fastapi import FastAPI, HTTPException, Query, Depends, Header
from pydantic import BaseModel
from typing import Optional, Literal
from datetime import datetime, timedelta
import uuid
import hashlib
import secrets

app = FastAPI()

# In-memory storage
ads: dict[str, dict] = {}
users: dict[str, dict] = {}  # id -> {username, password_hash, role: user|admin}
tokens: dict[str, dict] = {}  # token -> {user_id, expires}
TOKEN_TTL = timedelta(hours=48)
SECRET = "change-in-production"


def hash_password(password: str) -> str:
    return hashlib.sha256((password + SECRET).encode()).hexdigest()


def create_token(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    tokens[token] = {"user_id": user_id, "expires": datetime.utcnow() + TOKEN_TTL}
    return token


def get_user_by_token(authorization: Optional[str] = Header(None)) -> Optional[dict]:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization[7:]
    if token not in tokens:
        return None
    data = tokens[token]
    if datetime.utcnow() > data["expires"]:
        del tokens[token]
        return None
    uid = data["user_id"]
    u = users.get(uid)
    if not u:
        return None
    return {"id": uid, "username": u["username"], "role": u["role"]}


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
def login(body: LoginBody):
    for uid, u in users.items():
        if u["username"] == body.username and u["password_hash"] == hash_password(body.password):
            return {"token": create_token(uid)}
    raise HTTPException(status_code=401, detail="Invalid login or password")


# User routes
@app.get("/user")
def list_users(current: Optional[dict] = Depends(get_user_by_token)):
    if current is None:
        raise HTTPException(status_code=403, detail="Unauthorized")
    if current["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return [{"id": uid, "username": u["username"], "role": u["role"]} for uid, u in users.items()]


@app.get("/user/{user_id}")
def get_user(user_id: str, current: Optional[dict] = Depends(get_user_by_token)):
    if user_id not in users:
        raise HTTPException(status_code=404, detail="Not found")
    u = users[user_id]
    return {"id": user_id, "username": u["username"], "role": u["role"]}


@app.post("/user")
def create_user(body: UserCreate):
    for u in users.values():
        if u["username"] == body.username:
            raise HTTPException(status_code=400, detail="Username exists")
    uid = str(uuid.uuid4())
    users[uid] = {
        "username": body.username,
        "password_hash": hash_password(body.password),
        "role": body.role,
    }
    return {"id": uid, "username": body.username, "role": body.role}


@app.patch("/user/{user_id}")
def update_user(user_id: str, body: UserUpdate, current: Optional[dict] = Depends(get_user_by_token)):
    if user_id not in users:
        raise HTTPException(status_code=404, detail="Not found")
    if current is None:
        raise HTTPException(status_code=403, detail="Unauthorized")
    if current["role"] != "admin" and current["id"] != user_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    u = users[user_id]
    if body.role is not None and current["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    if body.username is not None:
        u["username"] = body.username
    if body.password is not None:
        u["password_hash"] = hash_password(body.password)
    if body.role is not None and current["role"] == "admin":
        u["role"] = body.role
    return {"id": user_id, "username": u["username"], "role": u["role"]}


@app.delete("/user/{user_id}")
def delete_user(user_id: str, current: Optional[dict] = Depends(get_user_by_token)):
    if user_id not in users:
        raise HTTPException(status_code=404, detail="Not found")
    if current is None:
        raise HTTPException(status_code=403, detail="Unauthorized")
    if current["role"] != "admin" and current["id"] != user_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    del users[user_id]
    return None


# Helpers for ads: need to add "owner_id" to ads and set current user id on token


def ad_to_response(ad_id: str, ad: dict) -> dict:
    return {
        "id": ad_id,
        "title": ad["title"],
        "description": ad["description"],
        "price": ad["price"],
        "author": ad["author"],
        "created_at": ad["created_at"],
        "owner_id": ad.get("owner_id"),
    }


# Advertisement routes
@app.post("/advertisement")
def create_advertisement(body: AdvertisementCreate, current: Optional[dict] = Depends(get_user_by_token)):
    if current is None:
        raise HTTPException(status_code=403, detail="Unauthorized")
    ad_id = str(uuid.uuid4())
    ads[ad_id] = {
        "title": body.title,
        "description": body.description,
        "price": body.price,
        "author": body.author,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "owner_id": current["id"],
    }
    return ad_to_response(ad_id, ads[ad_id])


@app.get("/advertisement/{advertisement_id}")
def get_advertisement(advertisement_id: str):
    if advertisement_id not in ads:
        raise HTTPException(status_code=404, detail="Not found")
    return ad_to_response(advertisement_id, ads[advertisement_id])


@app.patch("/advertisement/{advertisement_id}")
def update_advertisement(advertisement_id: str, body: AdvertisementUpdate, current: Optional[dict] = Depends(get_user_by_token)):
    if advertisement_id not in ads:
        raise HTTPException(status_code=404, detail="Not found")
    ad = ads[advertisement_id]
    if current is None:
        raise HTTPException(status_code=403, detail="Unauthorized")
    if current["role"] != "admin" and ad.get("owner_id") != current["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    if body.title is not None:
        ad["title"] = body.title
    if body.description is not None:
        ad["description"] = body.description
    if body.price is not None:
        ad["price"] = body.price
    if body.author is not None:
        ad["author"] = body.author
    return ad_to_response(advertisement_id, ad)


@app.delete("/advertisement/{advertisement_id}")
def delete_advertisement(advertisement_id: str, current: Optional[dict] = Depends(get_user_by_token)):
    if advertisement_id not in ads:
        raise HTTPException(status_code=404, detail="Not found")
    ad = ads[advertisement_id]
    if current is None:
        raise HTTPException(status_code=403, detail="Unauthorized")
    if current["role"] != "admin" and ad.get("owner_id") != current["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    del ads[advertisement_id]
    return None


@app.get("/advertisement")
def search_advertisements(
    title: Optional[str] = Query(None),
    description: Optional[str] = Query(None),
    price: Optional[float] = Query(None),
    author: Optional[str] = Query(None),
):
    out = []
    for ad_id, ad in ads.items():
        if title and title not in ad["title"]:
            continue
        if description and description not in ad["description"]:
            continue
        if price is not None and ad["price"] != price:
            continue
        if author and ad["author"] != author:
            continue
        out.append(ad_to_response(ad_id, ad))
    return out
