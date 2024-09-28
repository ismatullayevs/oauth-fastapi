from datetime import datetime, timedelta, timezone
import jwt
from config.settings import get_settings


settings = get_settings()


def create_jwt_token(data: dict, expires: timedelta) -> str:
    to_update = data.copy()
    expire = datetime.now(timezone.utc) + expires
    to_update.update({'exp': expire})
    encoded_jwt = jwt.encode(
        to_update, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt
