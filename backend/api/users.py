from fastapi import APIRouter, Depends, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from config.db import get_db
from models.user import User
from schemas.user import UserCreateSchema, UserSchema
from typing import Annotated
from passlib.context import CryptContext
from config.settings import get_settings
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
    Registers a new user by email and password. (full_name is optional)
    """

    if db.query(User).filter(User.email == form_data.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='User already exists')

    hashed_password = pwd_context.hash(form_data.password)
    db_user = User(
        **form_data.model_dump(exclude={'password'}), hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    user = UserSchema.model_validate(db_user)
    return user


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)],
                           db: Annotated[Session, Depends(get_db)]) -> UserSchema:
    """
    Returns the current user based on the token.
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

    return UserSchema.model_validate(user)


@router.get('/me')
async def get_me(db: Annotated[Session, Depends(get_db)],
                 user: Annotated[UserSchema, Depends(get_current_user)]) -> UserSchema:
    """
    Returns the user's data.
    """
    return user
