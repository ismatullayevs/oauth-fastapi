from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import Annotated
from schemas.user import UserSchema, UserUpdateSchema
from core.dependencies import get_current_active_user
from config.db import get_db


router = APIRouter(prefix='/users', tags=['users'])


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
