from fastapi import FastAPI
from core.db import engine, Base
from api.main import router


app = FastAPI()

Base.metadata.create_all(bind=engine)


app.include_router(router, prefix="/api")
