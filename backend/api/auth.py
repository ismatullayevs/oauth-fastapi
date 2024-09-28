from fastapi import APIRouter, Depends, HTTPException, status, Response, Cookie
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated
from sqlalchemy.orm import Session
from config.db import get_db
from models.user import User
from schemas.token import TokenSchema
from .users import pwd_context
from datetime import timedelta, timezone, datetime
from config.settings import get_settings

import jwt


router = APIRouter(prefix='/auth', tags=['auth'])

settings = get_settings()
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7


def create_jwt_token(data: dict, expires: timedelta) -> str:
    to_update = data.copy()
    expire = datetime.now(timezone.utc) + expires
    to_update.update({'exp': expire})
    encoded_jwt = jwt.encode(
        to_update, settings.SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


@router.post('/token')
async def login(response: Response,
                form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                db: Annotated[Session, Depends(get_db)]) -> TokenSchema:
    """
    Login endpoint. Returns a JWT token.
    """

    user = db.query(User).filter(User.email == form_data.username).first()

    if not user or not pwd_context.verify(form_data.password, str(user.hashed_password)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect email or password',
            headers={"WWW-Authenticate": "Bearer"},)

    access_token = create_jwt_token({'sub': user.email}, timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_jwt_token({'sub': user.email}, timedelta(
        minutes=REFRESH_TOKEN_EXPIRE_MINUTES))

    response.set_cookie(key='auth_token', value=refresh_token,
                        httponly=True, max_age=REFRESH_TOKEN_EXPIRE_MINUTES * 60)

    return TokenSchema(access_token=access_token, token_type='bearer')


@router.post('/refresh')
async def refresh_token(response: Response, auth_token: Annotated[str | None, Cookie()] = None):
    """
    Refresh token endpoint. Returns new access and refresh tokens.
    """

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Invalid token',
        headers={"WWW-Authenticate": "Bearer"},)

    if not auth_token:
        raise credentials_exception

    try:
        payload = jwt.decode(
            auth_token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get('sub')
        if email is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception

    access_token = create_jwt_token({'sub': email}, timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_jwt_token({'sub': email}, timedelta(
        minutes=REFRESH_TOKEN_EXPIRE_MINUTES))
    
    response.set_cookie(key='auth_token', value=refresh_token,
                        httponly=True, max_age=REFRESH_TOKEN_EXPIRE_MINUTES * 60)

    return TokenSchema(access_token=access_token, token_type='bearer')
