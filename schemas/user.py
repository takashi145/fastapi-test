from pydantic import BaseModel, Field, EmailStr


class UserCreate(BaseModel):
    username: str = Field(
        ...,
        min_length=1,
        max_length=50,
        nullable=False
    )
    email: EmailStr
    password: str = Field(
        ...,
        min_length=8,
        max_length=32,
        nullable=False
    )
    password_confirmation: str = Field(
        ...,
        min_length=8,
        max_length=32,
        nullable=False
    )
