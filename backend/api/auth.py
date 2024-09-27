from fastapi import APIRouter, Depends, HTTPException, status, Header
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


def create_access_token(data: dict) -> str:
    to_update = data.copy()
    expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = datetime.now(timezone.utc) + expires_delta
    to_update.update({'exp': expire})
    encoded_jwt = jwt.encode(
        to_update, settings.SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


@router.post('/token')
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
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

    access_token = create_access_token(
        {'sub': user.email, 'full_name': user.full_name})
    return TokenSchema(access_token=access_token, token_type='bearer')
