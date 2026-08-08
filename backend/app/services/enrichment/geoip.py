"""GeoIP enrichment using MaxMind GeoLite2 local database.

Per the implementation plan (section 1.4): local DB file, no per-request
external call needed.
"""

from __future__ import annotations

from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)

# Lazy-loaded reader instances
_city_reader = None
_asn_reader = None


def _get_city_reader():
    """Lazily load the GeoLite2-City database."""
    global _city_reader
    if _city_reader is None:
        try:
            import geoip2.database

            settings = get_settings()
            _city_reader = geoip2.database.Reader(settings.maxmind_db_path)
            log.info("geoip_city_db_loaded", path=settings.maxmind_db_path)
        except Exception as exc:
            log.warning("geoip_city_db_unavailable", error=str(exc))
            return None
    return _city_reader


def _get_asn_reader():
    """Lazily load the GeoLite2-ASN database."""
    global _asn_reader
    if _asn_reader is None:
        try:
            import geoip2.database

            settings = get_settings()
            _asn_reader = geoip2.database.Reader(settings.maxmind_asn_db_path)
            log.info("geoip_asn_db_loaded", path=settings.maxmind_asn_db_path)
        except Exception as exc:
            log.warning("geoip_asn_db_unavailable", error=str(exc))
            return None
    return _asn_reader


def enrich_geoip(ip: str) -> dict[str, Any]:
    """Look up GeoIP data for an IP address.

    Returns a dict matching the GeoInfo schema:
        {country, city, lat, lon, asn, org}
    """
    result: dict[str, Any] = {
        "country": "",
        "city": "",
        "lat": 0.0,
        "lon": 0.0,
        "asn": "",
        "org": "",
    }

    # City / location lookup
    city_reader = _get_city_reader()
    if city_reader:
        try:
            resp = city_reader.city(ip)
            result["country"] = resp.country.iso_code or ""
            result["city"] = resp.city.name or ""
            if resp.location:
                result["lat"] = resp.location.latitude or 0.0
                result["lon"] = resp.location.longitude or 0.0
        except Exception:
            log.debug("geoip_city_lookup_failed", ip=ip)

    # ASN / org lookup
    asn_reader = _get_asn_reader()
    if asn_reader:
        try:
            resp = asn_reader.asn(ip)
            result["asn"] = f"AS{resp.autonomous_system_number}" if resp.autonomous_system_number else ""
            result["org"] = resp.autonomous_system_organization or ""
        except Exception:
            log.debug("geoip_asn_lookup_failed", ip=ip)

    return result
