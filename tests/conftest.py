import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.db import Base
from app.services.auth import create_owner


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        owner = create_owner(
            session,
            "test-owner",
            "test-owner-password-123",
        )
        session.info["owner_id"] = owner.id
        yield session
    finally:
        session.close()
        engine.dispose()
