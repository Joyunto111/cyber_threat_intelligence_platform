"""Application Configuration and Settings Module.

Manages environment variables, threat intelligence API keys,
configurable risk scoring weights, rate limits, and security constraints.
"""

from typing import Dict, Any
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    # Application Info
    APP_NAME: str = "Cyber Threat Intelligence Analysis Platform"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "production"
    DEBUG: bool = False
    
    # Server Binding
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    FRONTEND_PORT: int = 8501
    
    # Database
    DATABASE_URL: str = "sqlite:///./threat_intel.db"
    
    # Threat Intelligence Provider API Keys (Optional - never invented)
    VIRUSTOTAL_API_KEY: str = Field(default="", description="VirusTotal API v3 key")
    ABUSEIPDB_API_KEY: str = Field(default="", description="AbuseIPDB API v2 key")
    URLHAUS_API_KEY: str = Field(default="", description="URLhaus API key")
    ALIENVAULT_OTX_API_KEY: str = Field(default="", description="AlienVault OTX API key")
    
    # Provider Rate Limits (requests per minute)
    VIRUSTOTAL_RPM: int = 4
    ABUSEIPDB_RPM: int = 20
    URLHAUS_RPM: int = 30
    ALIENVAULT_RPM: int = 30
    
    # Cache Configuration
    CACHE_ENABLED: bool = True
    CACHE_TTL_SECONDS: int = 3600  # 1 hour
    
    # Risk Scoring Configurable Weights (Must sum to ~1.0)
    WEIGHT_REPUTATION: float = 0.35
    WEIGHT_HEURISTICS: float = 0.25
    WEIGHT_COMMUNITY: float = 0.25
    WEIGHT_AI_ML: float = 0.15
    
    # Security & SSRF Protection
    ALLOW_PRIVATE_IPS: bool = False
    REQUEST_TIMEOUT_SECONDS: int = 5
    MAX_REDIRECTS: int = 3
    MAX_UPLOAD_SIZE_MB: int = 50
    USER_AGENT: str = "CTI-Analyzer/1.0 (+https://github.com/security/cti-platform)"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    def get_scoring_weights(self) -> Dict[str, float]:
        """Returns normalized scoring weights."""
        total = (self.WEIGHT_REPUTATION + 
                 self.WEIGHT_HEURISTICS + 
                 self.WEIGHT_COMMUNITY + 
                 self.WEIGHT_AI_ML)
        if total == 0:
            return {"reputation": 0.35, "heuristics": 0.25, "community": 0.25, "ai_ml": 0.15}
        return {
            "reputation": self.WEIGHT_REPUTATION / total,
            "heuristics": self.WEIGHT_HEURISTICS / total,
            "community": self.WEIGHT_COMMUNITY / total,
            "ai_ml": self.WEIGHT_AI_ML / total
        }


# Global settings singleton
settings = Settings()
