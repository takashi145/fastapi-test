from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from routers import auth
from fastapi_csrf_protect import CsrfProtect
from fastapi_csrf_protect.exceptions import CsrfProtectError
from schemas.user import CsrfSettings


app = FastAPI()
app.include_router(auth.router)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        'http://localhost:3000', 
        'http://localhost:8080'
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@CsrfProtect.load_config
def get_csrf_config():
    return CsrfSettings()


@app.get('/')
def index():
    return {'message': 'get'}


@app.post('/')
def post(request: Request, csrf_protect: CsrfProtect = Depends()):
    auth.verify_csrf(csrf_protect, request.headers)
    return {'message': 'post'}


@app.exception_handler(CsrfProtectError)
def csrf_protect_exception_handler(request: Request, exc: CsrfProtectError):
    return JSONResponse(
    status_code=exc.status_code,
        content={ 'detail':  exc.message
    }
)
