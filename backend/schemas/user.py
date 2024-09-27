from pydantic import BaseModel, EmailStr


class UserBaseSchema(BaseModel):
    email: EmailStr
    full_name: str | None = None


class UserCreateSchema(UserBaseSchema):
    password: str


class UserSchema(UserBaseSchema):
    is_active: bool = True

    model_config = {
        'from_attributes': True
    }


class UserInDB(UserSchema):
    hashed_password: str
