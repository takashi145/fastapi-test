from database import Base
from sqlalchemy import Column, null
from sqlalchemy.sql.sqltypes import Integer, String


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String)
    email = Column(String)
    refresh_token = Column(String, nullable=True)
    password = Column(String)
