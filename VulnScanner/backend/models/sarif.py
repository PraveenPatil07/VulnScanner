"""SARIF 2.1.0 models and generator."""

from typing import Optional

from pydantic import BaseModel, Field

from .finding import Finding, Severity
from .scan import ScanResult


class SarifMessage(BaseModel):
    text: str


class SarifArtifactLocation(BaseModel):
    uri: str
    uriBaseId: str = "%SRCROOT%"


class SarifRegion(BaseModel):
    startLine: int
    startColumn: int = 1
    snippet: Optional[dict] = None


class SarifPhysicalLocation(BaseModel):
    artifactLocation: SarifArtifactLocation
    region: SarifRegion


class SarifLocation(BaseModel):
    physicalLocation: SarifPhysicalLocation


class SarifReportingDescriptor(BaseModel):
    id: str
    name: str
    shortDescription: SarifMessage
    fullDescription: Optional[SarifMessage] = None
    helpUri: Optional[str] = None
    help: Optional[SarifMessage] = None
    properties: dict = Field(default_factory=dict)


class SarifToolComponent(BaseModel):
    name: str = "CVS-Scanner"
    version: str = "1.0.0"
    semanticVersion: str = "1.0.0"
    informationUri: str = "https://github.com/code-vuln-scanner/code-vuln-scanner"
    rules: list[SarifReportingDescriptor] = Field(default_factory=list)


class SarifTool(BaseModel):
    driver: SarifToolComponent


class SarifResult(BaseModel):
    ruleId: str
    ruleIndex: int = 0
    level: str
    message: SarifMessage
    locations: list[SarifLocation] = Field(default_factory=list)
    properties: dict = Field(default_factory=dict)


class SarifArtifact(BaseModel):
    location: SarifArtifactLocation
    length: Optional[int] = None


class SarifRun(BaseModel):
    tool: SarifTool
    results: list[SarifResult] = Field(default_factory=list)
    artifacts: list[SarifArtifact] = Field(default_factory=list)


class SarifLog(BaseModel):
    version: str = "2.1.0"
    schema_uri: str = Field(
        default="https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        alias="$schema",
    )
    runs: list[SarifRun] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


def _severity_to_level(severity: Severity) -> str:
    """Map finding severity to SARIF level."""
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    elif severity == Severity.MEDIUM:
        return "warning"
    return "note"


def generate_sarif(scan_result: ScanResult) -> dict:
    """Generate a SARIF 2.1.0 compliant JSON object from scan results."""
    rules_map: dict[str, int] = {}
    sarif_rules: list[SarifReportingDescriptor] = []
    sarif_results: list[SarifResult] = []
    artifacts_set: set[str] = set()

    for finding in scan_result.findings:
        if finding.rule_id not in rules_map:
            rule_index = len(sarif_rules)
            rules_map[finding.rule_id] = rule_index
            sarif_rules.append(
                SarifReportingDescriptor(
                    id=finding.rule_id,
                    name=finding.title,
                    shortDescription=SarifMessage(text=finding.title),
                    fullDescription=SarifMessage(text=finding.description),
                    helpUri=finding.references[0] if finding.references else None,
                    help=SarifMessage(text=finding.remediation),
                    properties={
                        "tags": [finding.cwe_id, finding.category.value],
                        "security-severity": str(finding.cvss_score),
                    },
                )
            )

        rule_index = rules_map[finding.rule_id]
        artifacts_set.add(finding.file_path)

        sarif_results.append(
            SarifResult(
                ruleId=finding.rule_id,
                ruleIndex=rule_index,
                level=_severity_to_level(finding.severity),
                message=SarifMessage(
                    text=f"{finding.title}: {finding.description}"
                ),
                locations=[
                    SarifLocation(
                        physicalLocation=SarifPhysicalLocation(
                            artifactLocation=SarifArtifactLocation(
                                uri=finding.file_path.replace("\\", "/")
                            ),
                            region=SarifRegion(
                                startLine=finding.line_number,
                                startColumn=max(1, finding.column_number),
                                snippet={"text": finding.matched_text},
                            ),
                        )
                    )
                ],
                properties={
                    "cwe": finding.cwe_id,
                    "cvss_score": finding.cvss_score,
                    "cvss_vector": finding.cvss_vector,
                    "mitre_attack": finding.mitre_attack_id,
                    "confidence": finding.confidence,
                    "severity": finding.severity.value,
                },
            )
        )

    sarif_artifacts = [
        SarifArtifact(location=SarifArtifactLocation(uri=uri.replace("\\", "/")))
        for uri in sorted(artifacts_set)
    ]

    sarif_log = SarifLog(
        runs=[
            SarifRun(
                tool=SarifTool(
                    driver=SarifToolComponent(rules=sarif_rules)
                ),
                results=sarif_results,
                artifacts=sarif_artifacts,
            )
        ]
    )

    result = sarif_log.model_dump(by_alias=True, exclude_none=True)
    return result
