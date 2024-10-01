from fastapi.testclient import TestClient
from sqlalchemy import create_engine, StaticPool
from sqlalchemy.orm import sessionmaker
from core.db import get_db, Base
from main import app
from core.config import settings


settings.ENVIRONMENT = "testing"
SQLALCHEMY_DATABASE_URL = "sqlite://"

client = TestClient(app)

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)


def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()  # type: ignore


app.dependency_overrides[get_db] = override_get_db

