"""Structured evidence shared by deterministic and optional semantic reviewers."""

from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class Evidence:
    rule_id: str
    source: str
    sink: str
    path: List[str] = field(default_factory=list)
    protections: List[str] = field(default_factory=list)
    missing_protections: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "source": self.source,
            "sink": self.sink,
            "path": self.path,
            "protections": self.protections,
            "missing_protections": self.missing_protections,
        }
