from fastapi import FastAPI, APIRouter
from config.db import engine
from models import user as user_model
from routes.users import router as user_router
from routes.auth import router as auth_router


user_model.Base.metadata.create_all(bind=engine)

app = FastAPI()

api_router = APIRouter(prefix='/api')
api_router.include_router(user_router)
api_router.include_router(auth_router)

app.include_router(api_router)
