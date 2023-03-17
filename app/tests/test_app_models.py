import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext

from ..database import Base
from ..main import app, get_db, SECRET_KEY, ALGORITHM
from ..models import User, Role

SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture()
def test_db():
    Base.metadata.create_all(bind=engine)
    yield TestingSessionLocal()
    Base.metadata.drop_all(bind=engine)


def test_user(test_db):
    username = "user"
    password = "secret"
    role = Role.ADMIN

    user = User(
        username=username,
        hashed_password=User.get_password_hash(password),
        role=role
    )
    test_db.add(user)
    test_db.commit()

    user = test_db.query(User).filter(User.username == username).first()
    assert user.username == username
    assert user.is_active
    assert user.role == Role.ADMIN.name
    assert user.verify_password(password, user.hashed_password)
    assert user.authenticate_user(test_db, username, password) == user
