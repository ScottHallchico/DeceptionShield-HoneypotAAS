"""Response rule configuration routes — GET /api/rules, PUT /api/rules/{id}."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select

from app.core.security import get_current_user
from app.db.session import get_db
from app.models.models import ResponseRule
from app.schemas.schemas import ResponseRuleCreate, ResponseRuleResponse, ResponseRuleUpdate

router = APIRouter(prefix="/api/rules", tags=["rules"])


@router.get("", response_model=list[ResponseRuleResponse])
async def list_rules(
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> list[ResponseRuleResponse]:
    """List all auto-response rules."""
    result = await db.execute(
        select(ResponseRule).order_by(ResponseRule.created_at.desc())
    )
    rules = result.scalars().all()
    return [ResponseRuleResponse.model_validate(r) for r in rules]


@router.post("", response_model=ResponseRuleResponse)
async def create_rule(
    body: ResponseRuleCreate,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> ResponseRuleResponse:
    """Create a new auto-response rule."""
    rule = ResponseRule(**body.model_dump())
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return ResponseRuleResponse.model_validate(rule)


@router.put("/{rule_id}", response_model=ResponseRuleResponse)
async def update_rule(
    rule_id: uuid.UUID,
    body: ResponseRuleUpdate,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> ResponseRuleResponse:
    """Update an existing auto-response rule."""
    result = await db.execute(
        select(ResponseRule).where(ResponseRule.id == rule_id)
    )
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    # Apply partial update
    update_data = body.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(rule, field, value)

    await db.commit()
    await db.refresh(rule)
    return ResponseRuleResponse.model_validate(rule)


@router.delete("/{rule_id}")
async def delete_rule(
    rule_id: uuid.UUID,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict:
    """Delete an auto-response rule."""
    result = await db.execute(
        select(ResponseRule).where(ResponseRule.id == rule_id)
    )
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    await db.delete(rule)
    await db.commit()
    return {"status": "deleted", "rule_id": str(rule_id)}
