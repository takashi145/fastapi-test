from fastapi import FastAPI
from routers import auth
import models
from database import engine

app = FastAPI()
app.include_router(auth.router)


@app.get('/')
def index():
    return 'Hello World!'


#models.Base.metadata.create_all(engine)
