from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MAX_CONFIG_BYTES = 100_000
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
SEVERITY_ORDER = {"info": 0, "warning": 1, "error": 2}


class ConfigError(ValueError):
    """Raised when the backup audit configuration is invalid."""


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    backup_set: str
    path: str | None
    message: str


@dataclass(frozen=True)
class AuditReport:
    source: str
    findings: tuple[Finding, ...]

    def counts(self) -> dict[str, int]:
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "summary": self.counts(),
            "findings": [asdict(finding) for finding in self.findings],
        }


def _load_config(config_path: Path) -> dict[str, Any]:
    try:
        if config_path.stat().st_size > MAX_CONFIG_BYTES:
            raise ConfigError(f"Configuration exceeds the {MAX_CONFIG_BYTES}-byte limit.")
        raw = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Could not read configuration: {exc.__class__.__name__}.") from exc
    try:
        config = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Configuration is not valid JSON (line {exc.lineno}).") from exc
    if not isinstance(config, dict) or not isinstance(config.get("backup_sets"), list) or not config["backup_sets"]:
        raise ConfigError("Configuration must contain a non-empty backup_sets array.")
    for index, backup_set in enumerate(config["backup_sets"]):
        if not isinstance(backup_set, dict):
            raise ConfigError(f"backup_sets[{index}] must be an object.")
        if not isinstance(backup_set.get("name"), str) or not backup_set["name"].strip():
            raise ConfigError(f"backup_sets[{index}].name must be a non-empty string.")
        if not isinstance(backup_set.get("path"), str) or not backup_set["path"].strip():
            raise ConfigError(f"backup_sets[{index}].path must be a non-empty string.")
        patterns = backup_set.get("include")
        if not isinstance(patterns, list) or not patterns or not all(isinstance(p, str) and p for p in patterns):
            raise ConfigError(f"backup_sets[{index}].include must be a non-empty array of file patterns.")
        age = backup_set.get("max_age_hours")
        if isinstance(age, bool) or not isinstance(age, (int, float)) or age <= 0:
            raise ConfigError(f"backup_sets[{index}].max_age_hours must be a positive number.")
        minimum = backup_set.get("minimum_files", 1)
        if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 1:
            raise ConfigError(f"backup_sets[{index}].minimum_files must be a positive integer.")
        if not isinstance(backup_set.get("verify_sidecars", False), bool):
            raise ConfigError(f"backup_sets[{index}].verify_sidecars must be true or false.")
    return config


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _find_matching_files(root: Path, patterns: list[str]) -> list[Path]:
    found: set[Path] = set()
    for pattern in patterns:
        for path in root.rglob(pattern):
            if path.is_file() and not path.is_symlink():
                found.add(path)
    return sorted(found)


def _add(
    findings: list[Finding],
    rule_id: str,
    severity: str,
    backup_set: str,
    path: Path | None,
    message: str,
) -> None:
    findings.append(Finding(rule_id, severity, backup_set, str(path) if path else None, message))


def _verify_sidecar(path: Path, backup_set: str, findings: list[Finding]) -> None:
    sidecar = Path(f"{path}.sha256")
    if not sidecar.is_file() or sidecar.is_symlink():
        _add(findings, "checksum-sidecar-missing", "error", backup_set, path, "No adjacent .sha256 checksum sidecar was found.")
        return
    try:
        tokens = sidecar.read_text(encoding="ascii").strip().split()
    except (OSError, UnicodeDecodeError):
        _add(findings, "checksum-sidecar-unreadable", "error", backup_set, sidecar, "Checksum sidecar could not be read as ASCII text.")
        return
    if not tokens or not SHA256_PATTERN.fullmatch(tokens[0]):
        _add(findings, "checksum-sidecar-invalid", "error", backup_set, sidecar, "Checksum sidecar must start with a 64-character SHA-256 digest.")
        return
    try:
        actual = _sha256(path)
    except OSError:
        _add(findings, "backup-unreadable", "error", backup_set, path, "Backup file could not be read for checksum verification.")
        return
    if actual.lower() != tokens[0].lower():
        _add(findings, "checksum-mismatch", "error", backup_set, path, "Backup content does not match its adjacent SHA-256 checksum.")


def audit_config(config_path: str | Path, *, now: datetime | None = None) -> AuditReport:
    config_file = Path(config_path).resolve()
    config = _load_config(config_file)
    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None:
        raise ValueError("now must be timezone-aware.")

    findings: list[Finding] = []
    for backup_set in config["backup_sets"]:
        name = backup_set["name"].strip()
        root_value = Path(backup_set["path"])
        root = root_value if root_value.is_absolute() else config_file.parent / root_value
        if root.is_symlink() or not root.is_dir():
            _add(findings, "backup-directory-missing", "error", name, root, "Configured backup directory is missing or is a symbolic link.")
            continue
        root = root.resolve()

        files = _find_matching_files(root, backup_set["include"])
        if len(files) < backup_set.get("minimum_files", 1):
            _add(findings, "backup-count-low", "error", name, root, f"Found {len(files)} matching backup file(s); the minimum is {backup_set.get('minimum_files', 1)}.")
        if not files:
            continue

        newest = max(files, key=lambda path: path.stat().st_mtime)
        newest_time = datetime.fromtimestamp(newest.stat().st_mtime, timezone.utc)
        age_seconds = (current_time.astimezone(timezone.utc) - newest_time).total_seconds()
        if age_seconds < -300:
            _add(findings, "backup-timestamp-in-future", "warning", name, newest, "Newest backup timestamp is more than five minutes in the future; check host clock synchronization.")
        age_hours = max(0.0, age_seconds / 3600)
        if age_hours > float(backup_set["max_age_hours"]):
            _add(findings, "backup-stale", "error", name, newest, f"Newest matching backup is {age_hours:.1f} hours old; the maximum is {float(backup_set['max_age_hours']):g} hours.")

        if backup_set.get("verify_sidecars", False):
            for path in files:
                _verify_sidecar(path, name, findings)

    findings.sort(key=lambda item: (-SEVERITY_ORDER[item.severity], item.backup_set, item.path or "", item.rule_id))
    return AuditReport(source=str(config_file), findings=tuple(findings))
