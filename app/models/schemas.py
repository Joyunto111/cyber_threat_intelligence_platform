"""Pydantic Models and Schemas for API Serialization."""

from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


# --- IOC Extraction and Validation ---

class IOCItem(BaseModel):
    raw: str
    normalized: str
    defanged: str
    type: str  # IP, DOMAIN, URL, HASH
    version: Optional[str] = None
    hash_type: Optional[str] = None


class TextExtractionRequest(BaseModel):
    text: str = Field(..., description="Raw text containing defanged or standard IOCs")


class TextExtractionResponse(BaseModel):
    total_found: int
    ips: List[IOCItem] = []
    domains: List[IOCItem] = []
    urls: List[IOCItem] = []
    hashes: List[IOCItem] = []


class DefangRequest(BaseModel):
    ioc: str
    defang: bool = True  # True to defang, False to refang


class DefangResponse(BaseModel):
    original: str
    result: str


# --- Provider and Analysis Models ---

class ProviderResult(BaseModel):
    provider_name: str
    status: str  # SUCCESS, FAILED, UNAVAILABLE, NOT_CONFIGURED
    is_malicious: Optional[bool] = None
    reputation_score: Optional[float] = None
    detection_count: int = 0
    total_engines: int = 0
    source_reliability: float = 1.0
    summary: Dict[str, Any] = {}
    error_message: Optional[str] = None
    coverage_available: bool = True


class ScoreExplanation(BaseModel):
    factor: str
    points_impact: float
    evidence: str
    source: str


class RiskAssessment(BaseModel):
    risk_score: float = Field(..., ge=0, le=100)
    risk_category: str  # LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN
    confidence_score: float = Field(..., ge=0, le=100)
    threat_classification: str
    explanations: List[ScoreExplanation] = []
    recommended_actions: List[str] = []
    weights_used: Dict[str, float] = {}


class RelationshipNode(BaseModel):
    id: str
    label: str
    type: str  # IP, DOMAIN, URL, HASH, CAMPAIGN, MALWARE_FAMILY
    risk_score: float
    category: str


class RelationshipEdge(BaseModel):
    source: str
    target: str
    relationship: str
    evidence: str
    source_provider: str
    confidence: float


class CorrelationGraph(BaseModel):
    nodes: List[RelationshipNode] = []
    edges: List[RelationshipEdge] = []


class AIAnalysisResult(BaseModel):
    threat_summary: str
    dga_prediction: Optional[Dict[str, Any]] = None
    phishing_prediction: Optional[Dict[str, Any]] = None
    anomalies_detected: List[str] = []
    disclaimer: str = (
        "AI/ML predictions are heuristic indicators and must not be treated as confirmed malicious findings."
    )


# --- Full Analysis Response ---

class FullIOCAnalysisResponse(BaseModel):
    indicator: str
    normalized: str
    defanged: str
    indicator_type: str
    timestamp: datetime
    
    # Core Intelligence
    risk_assessment: RiskAssessment
    ai_insights: AIAnalysisResult
    provider_results: List[ProviderResult] = []
    
    # Specific Module Intelligence
    module_details: Dict[str, Any] = {}
    
    # Graph & Correlations
    correlation_graph: CorrelationGraph
    
    # Metadata
    is_cached: bool = False
    investigation_id: Optional[int] = None


class AnalyzeRequest(BaseModel):
    indicator: str = Field(..., description="IP, Domain, URL, or Hash to analyze")
    use_cache: bool = True
    ai_analysis: bool = True


class BatchAnalyzeRequest(BaseModel):
    indicators: List[str] = Field(..., description="List of IOCs to analyze in batch")
    use_cache: bool = True


class BatchAnalyzeResponse(BaseModel):
    total_submitted: int
    total_processed: int
    results: List[FullIOCAnalysisResponse] = []


# --- Reporting Models ---

class ReportRequest(BaseModel):
    indicators: List[str] = Field(..., description="List of IOCs to include in report")
    report_type: str = Field("PDF", description="PDF, JSON, or CSV")
    title: Optional[str] = "Cyber Threat Intelligence Assessment"


class ReportResponse(BaseModel):
    report_id: int
    title: str
    report_type: str
    created_at: datetime
    download_url: str
    summary: Dict[str, Any] = {}


# --- Provider Status Model ---

class ProviderStatus(BaseModel):
    name: str
    configured: bool
    status: str
    rate_limit_rpm: int
    supported_types: List[str]
    notes: str
