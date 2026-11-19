"""Asynchronous Database Management and Session Handling."""

import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from openkai_engine.config import settings

# Setup engine with connection pooling and timeouts
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False
)

Base = declarative_base()

async def get_db():
    """FastAPI dependency for yielding database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

async def init_db():
    """Initialize database tables."""
    # Import all models to ensure they are registered with Base.metadata
    import openkai_engine.models.threat_intel  # noqa: F401
    import openkai_engine.models.assets        # noqa: F401
    import openkai_engine.models.investigations # noqa: F401
    import openkai_engine.models.notifications # noqa: F401
    import openkai_engine.models.audit         # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
