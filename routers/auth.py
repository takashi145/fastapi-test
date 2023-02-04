from fastapi import APIRouter, status, Depends, HTTPException, Request, Response, Cookie
from schemas.user import UserCreate, User
from schemas.token import Token
from database import get_db
from sqlalchemy.orm import Session
from typing import Optional
from datetime import timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from utils import authUtils
from fastapi_csrf_protect import CsrfProtect
import models
import config


ACCESS_TOKEN_EXPIRE_MINUTES = int(config.ACCESS_TOKEN_EXPIRE_MINUTES)

router = APIRouter(
    tags=['auth']
)

oauth2_schema = OAuth2PasswordBearer(tokenUrl="login")


@router.post('/register', status_code=status.HTTP_201_CREATED, response_model=User)
async def register(
    request: Request,
    user_data: UserCreate, 
    db: Session = Depends(get_db),
    csrf_protect: CsrfProtect = Depends()
):
    authUtils.verify_csrf(csrf_protect, request.headers)
    user = db.query(models.User).filter(models.User.email == user_data.email).first()
    if user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="username or email are already taken"
        )

    new_user = models.User(
        username=user_data.username,
        email=user_data.email,
        password=authUtils.get_password_hash(user_data.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@router.post('/login', response_model=Token)
async def login(
    request: Request,
    response: Response, 
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db: Session = Depends(get_db),
    csrf_protect: CsrfProtect = Depends()
):
    authUtils.verify_csrf(csrf_protect, request.headers)
    user = authUtils.authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = authUtils.create_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    refresh_token_expires = timedelta(days=90)
    refresh_token = authUtils.create_token(
        data={"sub": user.username}, expires_delta=refresh_token_expires
    )

    user.refresh_token = refresh_token

    db.commit()
    db.refresh(user)

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True
    )

    return {"access_token": access_token, "token_type": "bearer"}


@router.get('/user', status_code=status.HTTP_200_OK, response_model=User)
async def get_current_user(
    access_token: str = Depends(oauth2_schema), 
    db: Session = Depends(get_db)
):
    user = authUtils.get_user(access_token, db)
    return user


@router.get("/refresh")
async def refresh(
    request: Request, 
    refresh_token: Optional[str] = Cookie(None), 
    db: Session = Depends(get_db)
):

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = authUtils.get_user(refresh_token, db)

    if not user.refresh_token == refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = authUtils.create_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    return access_token


@router.post('/logout', status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    response: Response, 
    access_token: str = Depends(oauth2_schema), 
    db: Session = Depends(get_db),
    csrf_protect: CsrfProtect = Depends()
):
    authUtils.verify_csrf(csrf_protect, request.headers)
    user = authUtils.get_user(access_token, db)
    user.refresh_token = None
    db.commit()
    db.refresh(user)
    response.delete_cookie(key="refresh_token")
    return


@router.get('/csrf')
def form(request: Request, csrf_protect: CsrfProtect = Depends()):
    csrf_token = csrf_protect.generate_csrf()
    return {'csrf_token': csrf_token}
