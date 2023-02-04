from pydantic import BaseModel, Field, EmailStr, validator
import config


CSRF_KEY = config.CSRF_KEY

class CsrfSettings(BaseModel):
    secret_key:str = CSRF_KEY


class User(BaseModel):
    id: int
    username: str
    email: EmailStr

    class Config:
        orm_mode = True


class UserCreate(BaseModel):
    username: str = Field(
        min_length=1,
        max_length=50,
        nullable=False,
    )
    email: EmailStr
    password: str = Field(
        min_length=8,
        max_length=32,
        nullable=False
    )
    password_confirmation: str = Field(
        min_length=8,
        max_length=32,
        nullable=False
    )

    @validator("password_confirmation")
    def match(cls, value, values):
        if "password" in values and value != values["password"]:
            raise ValueError("password do not match")
        return value
