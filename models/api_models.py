from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum

class AttackType(str, Enum):
    NORMAL = "normal"
    CREDENTIAL_STUFFING = "credential_stuffing"
    SQL_INJECTION = "sql_injection"
    DATA_SCRAPING = "data_scraping"
    RATE_LIMIT_ABUSE = "rate_limit_abuse"
    BUSINESS_LOGIC_ABUSE = "business_logic_abuse"
    API_CHAIN_ATTACK = "api_chain_attack"

class APILog(BaseModel):
    timestamp: datetime
    user_id: str
    session_id: str
    ip_address: str
    user_agent: str
    endpoint: str
    method: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    request_body: Optional[Dict[str, Any]] = None
    response_code: int
    response_time_ms: int
    bytes_sent: int
    bytes_received: int
    attack_label: AttackType = AttackType.NORMAL
    attack_type: Optional[AttackType] = None
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    behavioral_anomaly: bool = False
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class UserProfile(BaseModel):
    user_id: str
    department: str
    normal_hours: List[str]
    typical_endpoints: List[str]
    access_pattern: str
    risk_category: str = "low"
    avg_requests_per_hour: float = 0.0
    last_login: Optional[datetime] = None

class DetectionResult(BaseModel):
    log_id: str
    timestamp: datetime
    risk_score: float
    attack_type: Optional[AttackType]
    confidence: float
    features: Dict[str, Any]
    explanation: str
    action_taken: str