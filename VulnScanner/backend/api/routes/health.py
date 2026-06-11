"""Health check endpoint."""

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check():
    """Basic health check endpoint."""
    return {"status": "healthy", "service": "code-vuln-scanner"}


@router.get("/ready")
async def readiness_check():
    """Readiness check - verifies all components are initialized."""
    from ...scanner.rule_engine import RuleEngine

    engine = RuleEngine()
    rule_count = engine.load_rules()

    return {
        "status": "ready",
        "rules_loaded": rule_count,
    }
