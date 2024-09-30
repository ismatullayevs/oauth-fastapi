from fastapi import APIRouter, Depends, HTTPException, status, Response, Cookie, Form
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated
from sqlalchemy.orm import Session
from config.db import get_db
from models.user import User
from passlib.context import CryptContext
from schemas.token import TokenSchema
from datetime import timedelta
from config.settings import get_settings
from utils import create_jwt_token
from core.email import send_activation_email
from schemas.user import UserCreateSchema, UserSchema
from schemas.token import ActivationToken
import jwt


router = APIRouter(prefix='/auth', tags=['auth'])
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
settings = get_settings()


@router.post('/register')
async def register_user(form_data: Annotated[UserCreateSchema, Form()],
                        db: Annotated[Session, Depends(get_db)]) -> UserSchema:
    """
    Registers a new user with full_name, email, and password
    """

    if db.query(User).filter(User.email == form_data.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='User already exists')

    hashed_password = pwd_context.hash(form_data.password)
    db_user = User(**form_data.model_dump(exclude={'password'}),
                   hashed_password=hashed_password,
                   is_active=False)

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    activation_expires = timedelta(settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    activation_token = create_jwt_token(
        {'sub': db_user.email}, activation_expires)
    send_activation_email(str(db_user.email), activation_token)

    return db_user


@router.get('/verify-email')
async def activate_user(token: ActivationToken,
                        db: Annotated[Session, Depends(get_db)]) -> UserSchema:
    """
    Activates the user based on the activation token.
    """

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate credentials',
        headers={'WWW-Authenticate': 'Bearer'},
    )

    try:
        payload = jwt.decode(token.token, settings.SECRET_KEY,
                             algorithms=[settings.ALGORITHM])
        email: str = payload.get('sub')
        if email is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception

    if bool(user.is_active):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='User is already active')

    user.is_active = True  # type: ignore
    db.commit()
    db.refresh(user)

    return user


@router.get('/resend-verification')
async def resend_verification(email: Annotated[str, Form()],
                              db: Annotated[Session, Depends(get_db)]):
    """
    Resends the activation email to the user.
    """

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='User not found')

    if bool(user.is_active):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='User is already active')

    activation_expires = timedelta(settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    activation_token = create_jwt_token(
        {'sub': user.email}, activation_expires)
    send_activation_email(str(user.email), activation_token)

    return {'message': 'Activation email has been sent'}


@router.post('/login')
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

    if not bool(user.is_active):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='User is not activated',
            headers={"WWW-Authenticate": "Bearer"},)

    access_token = create_jwt_token({'sub': user.email}, timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_jwt_token({'sub': user.email}, timedelta(
        minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES))

    response.set_cookie(key='auth_token', value=refresh_token,
                        httponly=True, max_age=settings.REFRESH_TOKEN_EXPIRE_MINUTES * 60)

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
            auth_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: str = payload.get('sub')
        if email is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception

    access_token = create_jwt_token({'sub': email}, timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_jwt_token({'sub': email}, timedelta(
        minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES))

    response.set_cookie(key='auth_token', value=refresh_token,
                        httponly=True, max_age=settings.REFRESH_TOKEN_EXPIRE_MINUTES * 60)

    return TokenSchema(access_token=access_token, token_type='bearer')
