import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app

@pytest.mark.asyncio
async def test_stats_integration():
    """Basic integration test to ensure /api/stats contract hasn't drifted."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/api/stats")
        assert response.status_code in (200, 401, 403)  # Just checking it exists and doesn't 500
        if response.status_code == 200:
            data = response.json()
            assert set(data.keys()) >= {"total_events", "top_attacking_countries", "events_per_honeypot"}

@pytest.mark.asyncio
async def test_events_integration():
    """Basic integration test to ensure /api/events contract hasn't drifted."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/api/events")
        assert response.status_code in (200, 401, 403)
        if response.status_code == 200:
            data = response.json()
            assert set(data.keys()) >= {"items", "total", "page", "page_size"}
