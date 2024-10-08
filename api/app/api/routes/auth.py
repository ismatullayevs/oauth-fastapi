from fastapi import APIRouter, Depends, HTTPException, status, Response, Cookie, Form
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated
from sqlalchemy.orm import Session
from core.db import get_db
from models.user import User
from schemas.token import TokenSchema
from core.config import settings
from core.email_utils import send_activation_email
from core.security import (hash_password, verify_password, create_access_token,
                           create_refresh_token, create_activation_token)
from schemas.user import UserCreateSchema, UserSchema
from schemas.token import ActivationToken
import jwt
import httpx


router = APIRouter()


@router.post('/register', status_code=status.HTTP_201_CREATED)
async def register_user(form_data: Annotated[UserCreateSchema, Form()],
                        db: Annotated[Session, Depends(get_db)]) -> UserSchema:
    """
    Registers a new user with full_name, email, and password
    """

    if db.query(User).filter(User.email == form_data.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='User already exists')

    hashed_password = hash_password(form_data.password)
    db_user = User(**form_data.model_dump(exclude={'password'}),
                   hashed_password=hashed_password,
                   is_active=False)

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    activation_token = create_activation_token(
        {'sub': db_user.email})
    send_activation_email(str(db_user.email), activation_token)

    return db_user


@router.post('/verify-email')
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
        if email is None or payload.get('type') != 'activation':
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

    activation_token = create_activation_token(
        {'sub': user.email})
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

    if not user or not verify_password(form_data.password, str(user.hashed_password)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect email or password',
            headers={"WWW-Authenticate": "Bearer"},)

    if not bool(user.is_active):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='User is not activated',
            headers={"WWW-Authenticate": "Bearer"},)

    access_token = create_access_token({'sub': user.email})
    refresh_token = create_refresh_token({'sub': user.email})

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
        if email is None or payload.get('type') != 'refresh':
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception

    access_token = create_access_token({'sub': email})
    refresh_token = create_refresh_token({'sub': email})

    response.set_cookie(key='auth_token', value=refresh_token,
                        httponly=True, max_age=settings.REFRESH_TOKEN_EXPIRE_MINUTES * 60)

    return TokenSchema(access_token=access_token, token_type='bearer')


@router.get('/google-login')
async def google_login():
    """
    Redirects to Google OAuth2 login page.
    """

    return {'url': settings.get_google_auth_url()}


@router.get('/google')
async def google_auth(resp: Response, code: str, db: Annotated[Session, Depends(get_db)]):
    """
    Google OAuth2 callback endpoint.
    """

    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code"
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(token_url, data=data)
        response_data = response.json()

    if 'error' in response_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=response_data['error'])

    async with httpx.AsyncClient() as client:
        response = await client.get('https://www.googleapis.com/oauth2/v2/userinfo',
                                    headers={'Authorization': f"Bearer {response_data['access_token']}"})
        user_data = response.json()

    user = db.query(User).filter(User.email == user_data['email']).first()
    if not user:
        user = User(email=user_data['email'],
                    full_name=user_data['name'],
                    is_active=True)
        db.add(user)
        db.commit()
        db.refresh(user)

    if not bool(user.is_active):
        user.is_active = True  # type: ignore
        db.commit()
        db.refresh(user)

    access_token = create_access_token({'sub': user.email})
    refresh_token = create_refresh_token({'sub': user.email})

    resp.set_cookie(key='auth_token', value=refresh_token,
                    httponly=True, max_age=settings.REFRESH_TOKEN_EXPIRE_MINUTES * 60)

    return TokenSchema(access_token=access_token, token_type='bearer')
