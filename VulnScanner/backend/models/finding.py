"""Finding and vulnerability category models."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnCategory(str, Enum):
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    SSRF = "SSRF"
    XXE = "XXE"
    INSECURE_DESERIALIZATION = "INSECURE_DESERIALIZATION"
    HARDCODED_SECRET = "HARDCODED_SECRET"
    HARDCODED_SECRETS = "HARDCODED_SECRETS"
    CRYPTO_WEAK = "CRYPTO_WEAK"
    INSECURE_CRYPTO = "INSECURE_CRYPTO"
    SSTI = "SSTI"
    OPEN_REDIRECT = "OPEN_REDIRECT"
    PROTOTYPE_POLLUTION = "PROTOTYPE_POLLUTION"
    RACE_CONDITION = "RACE_CONDITION"
    LOG_INJECTION = "LOG_INJECTION"
    FILE_INCLUSION = "FILE_INCLUSION"
    MASS_ASSIGNMENT = "MASS_ASSIGNMENT"
    BROKEN_AUTH = "BROKEN_AUTH"
    BROKEN_ACCESS_CONTROL = "BROKEN_ACCESS_CONTROL"
    INSECURE_UPLOAD = "INSECURE_UPLOAD"
    CSRF = "CSRF"
    IDOR = "IDOR"
    REGEX_DOS = "REGEX_DOS"
    MISCONFIG = "MISCONFIG"
    DEPENDENCY_CONFUSION = "DEPENDENCY_CONFUSION"
    FORMAT_STRING = "FORMAT_STRING"
    BUFFER_OVERFLOW = "BUFFER_OVERFLOW"
    LDAP_INJECTION = "LDAP_INJECTION"
    UNSAFE_CODE = "UNSAFE_CODE"
    INSECURE_COMMUNICATION = "INSECURE_COMMUNICATION"
    INSECURE_STORAGE = "INSECURE_STORAGE"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"
    INSECURE_CONFIGURATION = "INSECURE_CONFIGURATION"


class Finding(BaseModel):
    scan_id: str = Field(..., description="Parent scan UUID")
    rule_id: str = Field(..., min_length=1, max_length=50, description="Rule identifier e.g. PY-SQLI-001")
    category: VulnCategory
    severity: Severity
    title: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1, max_length=2000)
    file_path: str = Field(..., min_length=1, description="Relative to project root")
    line_number: int = Field(..., ge=1)
    column_start: int = Field(default=0, ge=0)
    column_end: int = Field(default=0, ge=0)
    code_snippet: str = Field(default="", description="Matched line with context")
    match_text: str = Field(default="", description="The exact matched string")
    cwe_id: str = Field(..., pattern=r"^CWE-\d+$")
    cvss_score: float = Field(..., ge=0.0, le=10.0)
    cvss_vector: str = Field(default="")
    mitre_attack_id: Optional[str] = Field(default=None)
    nist_csf: list[str] = Field(default_factory=list)
    owasp_top10: Optional[str] = Field(default=None)
    remediation: str = Field(default="")
    references: list[str] = Field(default_factory=list)
    confidence: str = Field(default="MEDIUM")
    false_positive_risk: Optional[str] = Field(default=None)
    language: str = Field(default="")
    language: str = Field(..., min_length=1)
    false_positive_risk: str = Field(..., pattern=r"^(LOW|MEDIUM|HIGH)$")

    @field_validator("file_path")
    @classmethod
    def validate_no_path_traversal(cls, v: str) -> str:
        if ".." in v or v.startswith("/") or v.startswith("\\"):
            raise ValueError("File path must be relative and cannot contain '..'")
        return v
