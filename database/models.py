"""
Data Models and Typed Entities for CloudSentinel.
Defines normalized security event schemas, website monitoring models,
alert lifecycles, and ML evaluation dataclasses.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List
from datetime import datetime


@dataclass
class NormalizedSecurityEvent:
    """
    Standardized security event schema normalized from diverse sources
    (Nginx, Apache, Webhook API, Cloudflare, AWS CloudTrail/WAF, or Simulated Stream).
    """
    event_id: Optional[str] = None
    website_id: Optional[int] = None
    website_domain: Optional[str] = None
    source_type: str = "Generic"  # 'Nginx', 'Apache', 'Webhook API', 'Cloudflare', 'AWS', 'Simulated'
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    client_ip: str = "127.0.0.1"
    request_method: str = "GET"
    request_path: str = "/"
    http_status: int = 200
    response_size_bytes: int = 512
    user_agent: str = "Mozilla/5.0"
    
    # Feature inputs for ML inference engine
    login_attempts: int = 1
    failed_attempts: int = 0
    request_count: int = 25
    file_access_count: int = 2
    data_transfer_mb: float = 0.5
    unusual_location: int = 0
    unusual_time: int = 0
    privilege_level: int = 1
    
    # Metadata & raw data
    is_sensitive_path: bool = False
    waf_action: Optional[str] = None
    raw_payload: Optional[str] = None
    fingerprint: Optional[str] = None

    def to_feature_dict(self) -> Dict[str, Any]:
        """Extracts the exact 8-feature numerical vector for ML models."""
        return {
            "login_attempts": int(self.login_attempts),
            "failed_attempts": int(self.failed_attempts),
            "request_count": int(self.request_count),
            "file_access_count": int(self.file_access_count),
            "data_transfer_mb": float(self.data_transfer_mb),
            "unusual_location": int(self.unusual_location),
            "unusual_time": int(self.unusual_time),
            "privilege_level": int(self.privilege_level)
        }

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WebsiteRegistration:
    """Represents an authorized monitored website."""
    id: Optional[int] = None
    name: str = ""
    domain: str = ""
    url: str = ""
    status: str = "ACTIVE"  # 'ACTIVE', 'PAUSED', 'STOPPED'
    reachability_status: str = "UNKNOWN"  # 'HEALTHY', 'DEGRADED', 'DOWN', 'UNKNOWN'
    security_status: str = "NORMAL"  # 'NORMAL', 'SUSPICIOUS', 'CRITICAL_THREAT', 'WAITING_FOR_EVENTS'
    api_key: str = ""
    event_count: int = 0
    threat_count: int = 0
    last_health_check: Optional[str] = None
    last_event_time: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HealthCheckResult:
    """Result of safe, read-only website reachability and security header inspection."""
    website_id: int
    url: str
    is_reachable: bool
    status_code: Optional[int] = None
    response_time_ms: float = 0.0
    server_header: Optional[str] = None
    security_headers: Dict[str, bool] = field(default_factory=dict)
    missing_headers: List[str] = field(default_factory=list)
    error_message: Optional[str] = None
    checked_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
