import json
import base64
import datetime
from unittest.mock import Mock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from jose import jwt

from ..database import Base
from ..main import app, get_db, SECRET_KEY, ALGORITHM, create_access_token
from ..models import User, Role

SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


Base.metadata.create_all(bind=engine)


def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)


@pytest.fixture()
def test_db():
    try:
        Base.metadata.create_all(bind=engine)
        yield TestingSessionLocal()
    finally:
        Base.metadata.drop_all(bind=engine)


def create_user(db, username, password, role):
    user = User.create_user(db, username, password, role)
    user.password = password
    return user


@pytest.fixture()
def user_role_admin(test_db):
    return create_user(test_db, "admin", "secret", Role.ADMIN.name)


@pytest.fixture()
def user_role_user(test_db):
    return create_user(test_db, "user", "secret", Role.USER.name)


def get_token(username, password):
    response = client.post(
        "/token",
        data={"username": username, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    data = response.json()
    return data["accessToken"]


@pytest.fixture()
def admin_token(user_role_admin):
    return get_token(user_role_admin.username, user_role_admin.password)


@pytest.fixture()
def user_token(user_role_user):
    return get_token(user_role_user.username, user_role_user.password)


def test_create_admin(test_db):
    username = "admin"

    expected_username = username
    expected_is_active = True
    expected_role = "ADMIN"
    expected_msg = "The administrator exists"

    response = client.post(
        "/register-admin/",
        data={"username": username, "password": "secret"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == expected_username
    assert data["isActive"] == expected_is_active
    assert data["role"] == expected_role

    response = client.post(
        "/register-admin/",
        data={"username": username, "password": "secret"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 403
    data = response.json()
    assert data["detail"] == expected_msg


def test_login(user_role_user):

    datetime_mock = Mock(wraps=datetime.datetime)
    utcnow_mock = datetime.datetime.utcnow()
    datetime_mock.utcnow.return_value = utcnow_mock

    datetime_mock_timedelta = Mock(wraps=datetime.timedelta)
    expires_delta = datetime.timedelta(minutes=3)
    datetime_mock_timedelta.return_value = expires_delta

    expire = utcnow_mock + expires_delta
    to_encode = {
        "sub": user_role_user.username,
        "exp": expire
    }
    expected_access_token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    with patch("app.main.datetime", new=datetime_mock):
        with patch("app.main.timedelta", new=datetime_mock_timedelta):
            response = client.post(
                "/token",
                data={"username": user_role_user.username, "password": user_role_user.password},
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            assert response.status_code == 200
            data = response.json()
            assert data["tokenType"] == "bearer"
            assert data["accessToken"] == expected_access_token


def test_login_incorrect_username_or_password(test_db):
    username = "user"
    password = "secret"

    response = client.post(
        "/token",
        data={"username": username, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 401
    data = response.json()
    assert data["detail"] == "Incorrect username or password"


def test_user(user_token):

    expected_user_username = "user"
    expected_user_is_active = True
    expected_user_role = Role.USER.name

    response = client.get(
        "/users/me/",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 200
    user_data = response.json()

    assert user_data["username"] == expected_user_username
    assert user_data["isActive"] == expected_user_is_active
    assert user_data["role"] == expected_user_role


def test_user_hacking_token(user_role_user):

    response = client.post(
        "/token",
        data={"username": user_role_user.username, "password": user_role_user.password},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )

    data = response.json()
    access_token = data["accessToken"]
    access_token = access_token.split(".")
    payload = json.loads(base64.b64decode(access_token[1]+"=="))
    payload["exp"] += 1000
    access_token[1] = str(base64.b64encode(json.dumps(payload).encode())[:-2])
    access_token = ".".join(access_token)

    response = client.get(
        "/users/me/",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 401
    user_data = response.json()
    assert user_data["detail"] == "Could not validate credentials"


def test_user_not_exist(test_db):

    access_token = create_access_token(
        data={"sub": "user"}, expires_delta=datetime.timedelta(minutes=5)
    )

    response = client.get(
        "/users/me/",
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == 401
    user_data = response.json()
    assert user_data["detail"] == "Could not validate credentials"


def test_admin_allowed(admin_token):
    response = client.get(
        "/only-admin/",
        headers={"Authorization": f"Bearer {admin_token}"}
    )

    assert response.status_code == 200
    data = response.json()
    assert data["detail"] == "success"


def test_admin_not_allowed(user_token):
    response = client.get(
        "/only-admin/",
        headers={"Authorization": f"Bearer {user_token}"}
    )

    assert response.status_code == 403
    data = response.json()
    assert data["detail"] == "Operation not permitted"
