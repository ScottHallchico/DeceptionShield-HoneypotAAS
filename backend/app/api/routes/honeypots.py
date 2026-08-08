"""Honeypot fleet management routes — GET /api/honeypots, POST /api/honeypots/{id}/redeploy."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select

from app.core.logging import get_logger
from app.core.security import get_current_user
from app.db.session import get_db
from app.models.models import HoneypotInstance
from app.schemas.schemas import HoneypotInstanceResponse, HoneypotRedeployRequest

log = get_logger(__name__)

router = APIRouter(prefix="/api/honeypots", tags=["honeypots"])


@router.get("", response_model=list[HoneypotInstanceResponse])
async def list_honeypots(
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> list[HoneypotInstanceResponse]:
    """Fleet status — all deployed honeypot instances."""
    result = await db.execute(
        select(HoneypotInstance).order_by(HoneypotInstance.deployed_at.desc())
    )
    instances = result.scalars().all()
    return [HoneypotInstanceResponse.model_validate(i) for i in instances]


@router.post("/{honeypot_id}/redeploy")
async def redeploy_honeypot(
    honeypot_id: str,
    body: HoneypotRedeployRequest | None = None,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict:
    """Trigger Terraform-driven redeployment / IP rotation of a specific honeypot.

    In production, this would invoke `terraform apply -target=module.honeypot[id]`
    or an ECS force-new-deployment. For the prototype, it updates the status
    and simulates the operation.
    """
    result = await db.execute(
        select(HoneypotInstance).where(HoneypotInstance.id == honeypot_id)
    )
    instance = result.scalar_one_or_none()

    if not instance:
        raise HTTPException(status_code=404, detail="Honeypot instance not found")

    # Mark as deploying
    instance.status = "deploying"
    await db.commit()

    log.info(
        "honeypot_redeploy_triggered",
        honeypot_id=honeypot_id,
        rotate_ip=body.rotate_ip if body else True,
    )

    # In production: trigger terraform or ECS redeployment here
    # For now, simulate by returning the action confirmation
    return {
        "status": "redeployment_initiated",
        "honeypot_id": honeypot_id,
        "rotate_ip": body.rotate_ip if body else True,
        "message": "Honeypot redeployment has been triggered. Status will update when complete.",
    }
