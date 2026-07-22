"""Provider Status and System Settings API Endpoints."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Dict, Any

from app.providers import provider_manager
from app.models.schemas import ProviderStatus
from app.config import settings

router = APIRouter(prefix="/config", tags=["Configuration & Methodology"])


class WeightsUpdateRequest(BaseModel):
    weight_reputation: float = Field(..., ge=0.0, le=1.0)
    weight_heuristics: float = Field(..., ge=0.0, le=1.0)
    weight_community: float = Field(..., ge=0.0, le=1.0)
    weight_ai_ml: float = Field(..., ge=0.0, le=1.0)


@router.get("/providers", response_model=List[ProviderStatus], summary="List Threat Intelligence Provider States")
def get_provider_statuses():
    """Returns the operational status, rate limits, and supported indicator types for each provider.
    Never exposes raw API keys.
    """
    return provider_manager.get_provider_statuses()


@router.get("/weights", summary="Get Configurable Risk Scoring Weights")
def get_scoring_weights():
    """Returns the current mathematical weights utilized by the risk scoring engine."""
    return {
        "raw_weights": {
            "reputation": settings.WEIGHT_REPUTATION,
            "heuristics": settings.WEIGHT_HEURISTICS,
            "community": settings.WEIGHT_COMMUNITY,
            "ai_ml": settings.WEIGHT_AI_ML
        },
        "normalized_weights": settings.get_scoring_weights(),
        "methodology": {
            "formula": "RiskScore = (Reputation * W_rep) + (Heuristics * W_heur) + (Community * W_comm) + (AI_ML * W_aiml)",
            "ranges": {
                "LOW": "0 - 29",
                "MEDIUM": "30 - 69",
                "HIGH": "70 - 89",
                "CRITICAL": "90 - 100"
            }
        }
    }


@router.post("/weights", summary="Update Risk Scoring Weights")
def update_scoring_weights(request: WeightsUpdateRequest):
    """Dynamically modifies the risk scoring engine weights."""
    total = (
        request.weight_reputation +
        request.weight_heuristics +
        request.weight_community +
        request.weight_ai_ml
    )
    if total <= 0:
        raise HTTPException(status_code=400, detail="Weights sum must be greater than zero.")

    settings.WEIGHT_REPUTATION = request.weight_reputation
    settings.WEIGHT_HEURISTICS = request.weight_heuristics
    settings.WEIGHT_COMMUNITY = request.weight_community
    settings.WEIGHT_AI_ML = request.weight_ai_ml

    return {
        "status": "updated",
        "new_weights": settings.get_scoring_weights()
    }
