from fastapi import APIRouter, Depends, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from config.db import get_db
from models.user import User
from schemas.user import UserCreateSchema, UserSchema, UserUpdateSchema
from typing import Annotated
from passlib.context import CryptContext
from config.settings import get_settings
from mail import send_activation_email
from utils import create_jwt_token
from datetime import timedelta
from schemas.token import ActivationToken
import jwt


router = APIRouter(prefix='/users', tags=['users'])

settings = get_settings()
SECRET_KEY = settings.SECRET_KEY
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@router.post('/')
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


@router.get('/activate')
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
        payload = jwt.decode(token.token, SECRET_KEY, algorithms=['HS256'])
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
    
    user.is_active = True # type: ignore
    db.commit()
    db.refresh(user)

    return user


@router.get('/resend-activation')
async def resend_activation(email: Annotated[str, Form()],
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


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)],
                           db: Annotated[Session, Depends(get_db)]) -> UserSchema:
    """
    Returns the current user based on the authorization token (JWT).
    """

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate credentials',
        headers={'WWW-Authenticate': 'Bearer'},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        email: str = payload.get('sub')
        if email is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception

    return user


async def get_current_active_user(current_user: Annotated[UserSchema, Depends(get_current_user)]) -> UserSchema:
    """
    Returns the current user if it is active.
    """

    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='Inactive user')
    return current_user


@router.get('/me')
async def get_user(db: Annotated[Session, Depends(get_db)],
                   user: Annotated[UserSchema, Depends(get_current_active_user)]) -> UserSchema:
    """
    Returns the current user
    """
    return user


@router.put('/me')
async def update_user(db: Annotated[Session, Depends(get_db)],
                      user: Annotated[UserSchema, Depends(get_current_active_user)],
                      form_data: UserUpdateSchema) -> UserSchema:
    """
    Updates the user's data.
    """

    for key, value in form_data.model_dump().items():
        setattr(user, key, value)

    db.commit()
    db.refresh(user)

    return user
