import enum

from sqlalchemy import Column, Integer, String, Enum, Boolean
from passlib.context import CryptContext


from .database import Base

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class Role(str, enum.Enum):
    ADMIN = "ADMIN"
    USER = "USER"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    role = Column(Enum(Role))

    @staticmethod
    def get_password_hash(password):
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password, hashed_password):
        return pwd_context.verify(plain_password, hashed_password)

    @classmethod
    def authenticate_user(cls, db, username: str, password: str):
        user = db.query(cls).filter(cls.username == username).first()
        if not user:
            return False
        if not cls.verify_password(password, user.hashed_password):
            return False
        return user

    @classmethod
    def create_user(cls, db, username, password, role):
        user = cls(
            username=username,
            hashed_password=cls.get_password_hash(password),
            role=role
        )
        db.add(user)
        db.commit()

        return user
