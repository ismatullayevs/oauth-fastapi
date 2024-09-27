from fastapi import FastAPI, APIRouter
from config.db import engine
from models import user as user_model
from api.users import router as user_router
from api.auth import router as auth_router


user_model.Base.metadata.create_all(bind=engine)

app = FastAPI()

api_router = APIRouter(prefix='/api')
api_router.include_router(user_router)
api_router.include_router(auth_router)

app.include_router(api_router)
