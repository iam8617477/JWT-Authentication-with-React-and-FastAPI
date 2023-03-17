from enum import Enum
from typing import Union

from fastapi_camelcase import CamelModel


class Token(CamelModel):
    access_token: str
    token_type: str


class TokenData(CamelModel):
    username: Union[str, None] = None


class Role(str, Enum):
    ADMIN = "ADMIN"
    USER = "USER"


class User(CamelModel):
    username: str
    is_active: Union[bool, None] = None
    role: Role

    class Config:
        orm_mode = True
