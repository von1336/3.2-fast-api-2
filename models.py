"""
Модели SQLAlchemy: User и Advertisement.
"""
from sqlalchemy import Column, String, Float, DateTime, ForeignKey, Text
from datetime import datetime
from database import Base
import uuid


def generate_uuid():
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    username = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(64), nullable=False)
    role = Column(String(20), nullable=False, default="user")  # user | admin


class Advertisement(Base):
    __tablename__ = "advertisements"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    price = Column(Float, nullable=False)
    author = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    owner_id = Column(String(36), ForeignKey("users.id"), nullable=True)
