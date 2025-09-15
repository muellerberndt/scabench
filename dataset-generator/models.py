from dataclasses import dataclass, field, asdict
from typing import List, Optional
from datetime import datetime


@dataclass
class Vulnerability:
    finding_id: str
    severity: str
    title: str
    description: str
    
    def to_dict(self):
        return asdict(self)


@dataclass
class Codebase:
    codebase_id: str
    repo_url: str
    commit: str
    tree_url: str
    tarball_url: Optional[str] = None
    notes: Optional[str] = None
    
    def to_dict(self):
        result = asdict(self)
        return {k: v for k, v in result.items() if v is not None}


@dataclass
class Project:
    project_id: str
    name: str
    platform: str
    codebases: List[Codebase] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    contest_date: Optional[datetime] = None
    report_url: Optional[str] = None
    language: Optional[str] = None

    def to_dict(self):
        result = {
            "project_id": self.project_id,
            "name": self.name,
            "platform": self.platform,
            "codebases": [cb.to_dict() for cb in self.codebases],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities]
        }
        if self.report_url:
            result["report_url"] = self.report_url
        if self.language:
            result["language"] = self.language
        return result


@dataclass
class Dataset:
    dataset_id: str
    period_start: str
    period_end: str
    schema_version: str = "1.0.0"
    projects: List[Project] = field(default_factory=list)
    
    def to_dict(self):
        return {
            "dataset_id": self.dataset_id,
            "period_start": self.period_start,
            "period_end": self.period_end,
            "schema_version": self.schema_version,
            "projects": [p.to_dict() for p in self.projects]
        }
    
    def to_json(self):
        import json
        return json.dumps(self.to_dict(), indent=2)