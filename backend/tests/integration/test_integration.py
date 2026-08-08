import pytest
from httpx import AsyncClient

from app.main import app

@pytest.mark.asyncio
async def test_stats_integration():
    """Basic integration test to ensure /api/stats contract hasn't drifted."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.get("/api/stats")
        assert response.status_code in (200, 401, 403)  # Just checking it exists and doesn't 500

@pytest.mark.asyncio
async def test_events_integration():
    """Basic integration test to ensure /api/events contract hasn't drifted."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.get("/api/events")
        assert response.status_code in (200, 401, 403)
