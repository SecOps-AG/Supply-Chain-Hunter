"""Shared records for a release diff and its classification."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class ReleaseMeta:
    ecosystem: str
    name: str
    new_version: str
    old_version: str | None
    rank: int | None = None
    registry_url: str = ""
    old_publishers: frozenset[str] = frozenset()
    new_publishers: frozenset[str] = frozenset()
    old_time: datetime | None = None
    new_time: datetime | None = None


@dataclass
class FileDiff:
    path: str
    category: str
    diff_text: str
    added_text: str
    old_text: str
    new_text: str


@dataclass
class CodeFeatures:
    lifecycle_script_edits: int = 0
    new_dependency_names: list[str] = field(default_factory=list)
    publisher_changed: bool = False
    release_gap_hours: float | None = None
    short_release_gap: bool = False
    high_entropy_additions: int = 0
    literal_decode_exec: bool = False
    literal_shell: bool = False
    literal_raw_ip: bool = False
    literal_credential: bool = False
    credential_kind: str = ""
    install_paths: list[str] = field(default_factory=list)
    phantom_runtime_dependencies: list[str] = field(default_factory=list)
    compound_install_payload: bool = False
    literal_xor: bool = False
    literal_encoded_import: bool = False
    literal_minified_payload: bool = False
    literal_new_host: bool = False
    literal_persistence: bool = False
    binary_media_changes: int = 0
    dependency_typosquats: list[str] = field(default_factory=list)
    package_typosquat: str = ""
    entrypoint_payload: bool = False
    install_sidecar: bool = False
    behavior_chains: list[str] = field(default_factory=list)
    runtime_behavior_chains: list[str] = field(default_factory=list)
    new_binary: bool = False
    rule_report: RuleReport | None = None

    @property
    def new_dependency_count(self) -> int:
        return len(self.new_dependency_names)

    def static_hot(self) -> bool:
        return bool(
            self.lifecycle_script_edits
            or self.literal_decode_exec
            or self.literal_shell
            or self.literal_raw_ip
            or self.literal_credential
            or self.high_entropy_additions
            or self.literal_xor
            or self.literal_encoded_import
            or self.literal_minified_payload
            or self.dependency_typosquats
            or self.package_typosquat
            or self.entrypoint_payload
            or self.install_sidecar
            or self.behavior_chains
        )

    def static_alert(self) -> bool:
        """Install hook and a payload in the same added script, not scattered literals."""
        return self.compound_install_payload

    def signal_list(self) -> list[str]:
        signals: list[str] = []
        if self.lifecycle_script_edits:
            signals.append("lifecycle_script_edits")
        if self.new_dependency_names:
            shown = ",".join(self.new_dependency_names[:12])
            signals.append(f"new_dependency:{shown}")
        if self.publisher_changed:
            signals.append("publisher_changed")
        if self.short_release_gap:
            signals.append("short_release_gap")
        if self.high_entropy_additions:
            signals.append("high_entropy_additions")
        if self.literal_decode_exec:
            signals.append("literal_decode_exec")
        if self.literal_shell:
            signals.append("literal_shell")
        if self.literal_raw_ip:
            signals.append("literal_raw_ip")
        if self.literal_credential:
            signals.append("literal_credential")
        if self.phantom_runtime_dependencies:
            shown = ",".join(self.phantom_runtime_dependencies[:12])
            signals.append(f"phantom_runtime_dependency:{shown}")
        if self.compound_install_payload:
            signals.append("compound_install_payload")
        if self.literal_xor:
            signals.append("literal_xor")
        if self.literal_encoded_import:
            signals.append("literal_encoded_import")
        if self.literal_minified_payload:
            signals.append("literal_minified_payload")
        if self.literal_new_host:
            signals.append("literal_new_host")
        if self.literal_persistence:
            signals.append("literal_persistence")
        if self.binary_media_changes:
            signals.append("binary_media_change")
        if self.dependency_typosquats:
            shown = ",".join(self.dependency_typosquats[:12])
            signals.append(f"dependency_typosquat:{shown}")
        if self.package_typosquat:
            signals.append(f"typosquat_name:{self.package_typosquat}")
        if self.entrypoint_payload:
            signals.append("entrypoint_payload")
        if self.install_sidecar:
            signals.append("install_sidecar")
        for text in self.behavior_chains[:4]:
            signals.append(f"behavior_chain:{text}")
        for text in self.runtime_behavior_chains[:4]:
            signals.append(f"runtime_behavior_chain:{text}")
        if self.new_binary:
            signals.append("new_binary")
        if self.rule_report is not None:
            signals.extend(self.rule_report.signals())
        return signals


@dataclass(frozen=True)
class RuleHit:
    """One deterministic rule match on text this release added."""

    rule: str
    tier: str
    path: str
    line: int
    matched: str
    summary: str = ""


@dataclass
class RuleReport:
    """What the deterministic rule pack found in one release diff."""

    verdict: str = "nothing"
    hits: list[RuleHit] = field(default_factory=list)
    info: list[RuleHit] = field(default_factory=list)
    unscanned: list[tuple[str, str]] = field(default_factory=list)
    notes: list[tuple[str, str]] = field(default_factory=list)
    pack_version: str = ""
    elapsed_ms: float = 0.0
    # Floor level name ("review" or "alert") for each promoted rule that hit.
    strong_floors: dict[str, str] = field(default_factory=dict)

    @property
    def strong_hits(self) -> list[RuleHit]:
        return [hit for hit in self.hits if hit.tier == "strong"]

    def hits_by_path(self) -> dict[str, list[RuleHit]]:
        found: dict[str, list[RuleHit]] = {}
        for hit in self.hits:
            found.setdefault(hit.path, []).append(hit)
        return found

    def signals(self) -> list[str]:
        """Row signals: the verdict, up to 12 hit rules (strong first), then unscanned reasons."""
        found: list[str] = []
        if self.verdict == "malicious":
            found.append("rule_malicious")
        elif self.verdict == "unsure":
            found.append("rule_unsure")
        ordered = sorted(self.hits, key=lambda hit: hit.tier != "strong")
        rules: list[str] = []
        for hit in ordered:
            if hit.rule not in rules:
                rules.append(hit.rule)
        found.extend(f"rule:{rule}" for rule in rules[:12])
        reasons: list[str] = []
        for _path, reason in self.unscanned:
            if reason not in reasons:
                reasons.append(reason)
        found.extend(reasons)
        return found

    def hit_dicts(self, limit: int = 40) -> list[dict]:
        ordered = sorted(self.hits, key=lambda hit: hit.tier != "strong")
        return [
            {
                "rule": hit.rule,
                "tier": hit.tier,
                "path": hit.path,
                "line": hit.line,
                "matched_text": hit.matched,
                "summary": hit.summary,
            }
            for hit in ordered[:limit]
        ]


@dataclass
class Classification:
    ecosystem: str
    name: str
    old_version: str | None
    new_version: str
    rank: int | None
    registry_url: str
    band: str
    malice_probability: float
    jev_model_id: str
    attack_family: str = "none"
    subtype: str | None = None
    family_probabilities: dict[str, float] = field(default_factory=dict)
    cause: str = "unknown"
    cause_probabilities: dict[str, float] = field(default_factory=dict)
    subtype_probabilities: dict[str, float] = field(default_factory=dict)
    blast_radius_score: float | None = None
    blast_radius_label: str | None = None
    data_collection_score: float | None = None
    capability_nouls: dict[str, float] = field(default_factory=dict)
    noul_probabilities: dict[str, float] = field(default_factory=dict)
    signals: list[str] = field(default_factory=list)
    pass_d_agreed: bool = False
    pass_d_ran: bool = False
    reviewer_noul: float = 0.0
    child_findings: list[dict] = field(default_factory=list)
    needs_llm_review: bool = False
    defer_reason: str = ""
    rule_verdict: str = ""
    rule_hits: list[dict] = field(default_factory=list)
    rule_pack: str = ""
    # GitHub Actions only: tag, old and new commit, and the event kind. Empty for npm and PyPI.
    action_ref: dict = field(default_factory=dict)
