from pydantic import BaseModel, EmailStr, Field
from datetime import datetime


class UserBaseSchema(BaseModel):
    full_name: str | None = None


class UserCreateSchema(UserBaseSchema):
    email: EmailStr
    password: str


class UserUpdateSchema(UserBaseSchema):
    pass


class UserSchema(UserBaseSchema):
    id: int
    email: EmailStr
    is_active: bool = True
    created_at: datetime
    updated_at: datetime

    model_config = {
        'from_attributes': True
    }


class UserInDB(UserSchema):
    hashed_password: str
