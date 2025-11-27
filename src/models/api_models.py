from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel

class AttackType(str, Enum):
    CREDENTIAL_STUFFING = "credential_stuffing"
    SQL_INJECTION = "sql_injection"
    DATA_SCRAPING = "data_scraping"
    NORMAL = "normal"

class APILog(BaseModel):
    timestamp: datetime
    user_id: str
    session_id: str
    ip_address: str
    user_agent: str
    endpoint: str
    method: str
    parameters: Dict[str, Any]
    request_body: Optional[Dict[str, Any]] = None
    response_code: int
    response_time_ms: int
    bytes_sent: int
    bytes_received: int
    attack_label: Optional[str] = None
    attack_type: Optional[AttackType] = None
    risk_score: float = 0.0
    behavioral_anomaly: bool = False

class UserProfile(BaseModel):
    user_id: str
    department: str
    normal_hours: List[str]
    typical_endpoints: List[str]
    access_pattern: str
    risk_category: str
    avg_requests_per_hour: float
    last_login: datetime

class DetectionResult(BaseModel):
    log_id: str
    timestamp: datetime
    risk_score: float
    attack_type: Optional[str] = None
    confidence: float
    features: Dict[str, Any]
    explanation: Optional[str] = None
    action_taken: str
