import os
from os.path import join, dirname
from dotenv import load_dotenv

env_path = join(dirname(__file__), '.env')
load_dotenv(env_path)

SECRET_KEY = os.environ.get("SECRET_KEY")
ALGORITHM = os.environ.get("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES")

