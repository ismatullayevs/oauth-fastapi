from datetime import datetime, timedelta, timezone
import jwt
from passlib.context import CryptContext
from core.config import settings


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_jwt_token(data: dict, expires: timedelta) -> str:
    expire = datetime.now(timezone.utc) + expires
    encoded_jwt = jwt.encode({**data, "exp": expire},
                             settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def create_access_token(data: dict) -> str:
    expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return create_jwt_token({**data, "type": "access"}, expires)


def create_refresh_token(data: dict) -> str:
    expires = timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    return create_jwt_token({**data, "type": "refresh"}, expires)


def create_activation_token(data: dict) -> str:
    expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return create_jwt_token({**data, "type": "activation"}, expires)
