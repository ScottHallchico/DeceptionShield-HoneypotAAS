"""AI Threat Assistant route — POST /api/assistant/query."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.security import get_current_user
from app.schemas.schemas import AssistantQueryRequest, AssistantQueryResponse
from app.services.assistant.assistant import handle_assistant_query

router = APIRouter(prefix="/api/assistant", tags=["assistant"])


@router.post("/query", response_model=AssistantQueryResponse)
async def query_assistant(
    body: AssistantQueryRequest,
    user=Depends(get_current_user),
) -> AssistantQueryResponse:
    """Natural-language query against the honeypot event data.

    Uses hybrid retrieval (structured SQL + pgvector semantic search)
    grounded through Claude API — see section 1.11 of the implementation plan.
    """
    result = await handle_assistant_query(
        question=body.question,
        conversation_id=body.conversation_id,
        user_id=user.get("user_id", "anonymous"),
    )
    return AssistantQueryResponse(**result)
