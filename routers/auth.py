from fastapi import APIRouter, status, Depends, HTTPException
from schemas.user import UserCreate
from database import get_db
from sqlalchemy.orm import Session
from models import User
from passlib.context import CryptContext

router = APIRouter(
    tags=['auth']
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str):
    return pwd_context.hash(password)


@router.post('/register', status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate, db: Session = Depends(get_db)):
    if user.password != user.password_confirmation:
        raise HTTPException(status.HTTP_400_BAD_REQUEST)

    new_user = User(
        username=user.username,
        email=user.email,
        password=get_password_hash(user.password)
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user
