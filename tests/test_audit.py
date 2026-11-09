import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from backup_sentinel.audit import ConfigError, audit_config
from backup_sentinel.cli import main


def write_config(path, root, **overrides):
    backup_set = {
        "name": "database-nightly",
        "path": str(root),
        "include": ["*.sql.gz"],
        "max_age_hours": 24,
        "minimum_files": 1,
        "verify_sidecars": False,
    }
    backup_set.update(overrides)
    path.write_text(json.dumps({"backup_sets": [backup_set]}), encoding="utf-8")


def test_fresh_backup_and_valid_sidecar_pass(tmp_path):
    root = tmp_path / "backups"
    root.mkdir()
    backup = root / "db.sql.gz"
    backup.write_bytes(b"synthetic backup data")
    backup.with_suffix(backup.suffix + ".sha256").write_text(
        f"{hashlib.sha256(backup.read_bytes()).hexdigest()}  db.sql.gz\n",
        encoding="ascii",
    )
    config = tmp_path / "sentinel.json"
    write_config(config, root, verify_sidecars=True)

    report = audit_config(config)

    assert report.findings == ()
    assert report.counts()["error"] == 0


def test_detects_stale_backup_and_checksum_mismatch(tmp_path):
    root = tmp_path / "backups"
    root.mkdir()
    backup = root / "db.sql.gz"
    backup.write_bytes(b"backup was modified")
    backup.with_suffix(backup.suffix + ".sha256").write_text("0" * 64 + "  db.sql.gz\n", encoding="ascii")
    config = tmp_path / "sentinel.json"
    write_config(config, root, verify_sidecars=True, max_age_hours=1)
    now = datetime.fromtimestamp(backup.stat().st_mtime, timezone.utc) + timedelta(days=2)

    report = audit_config(config, now=now)

    ids = {finding.rule_id for finding in report.findings}
    assert {"backup-stale", "checksum-mismatch"} <= ids


def test_warns_when_backup_timestamp_is_far_in_the_future(tmp_path):
    root = tmp_path / "backups"
    root.mkdir()
    backup = root / "db.sql.gz"
    backup.write_bytes(b"synthetic backup")
    now = datetime.now(timezone.utc)
    future_timestamp = now.timestamp() + 900
    os.utime(backup, (future_timestamp, future_timestamp))
    config = tmp_path / "sentinel.json"
    write_config(config, root)

    report = audit_config(config, now=now)

    assert "backup-timestamp-in-future" in {finding.rule_id for finding in report.findings}


def test_reports_missing_directory_and_insufficient_count(tmp_path):
    backup_root = tmp_path / "backups"
    backup_root.mkdir()
    (backup_root / "one.sql.gz").write_bytes(b"synthetic")
    config = tmp_path / "sentinel.json"
    write_config(config, backup_root, minimum_files=2)

    report = audit_config(config)

    assert "backup-count-low" in {finding.rule_id for finding in report.findings}


def test_rejects_invalid_configuration(tmp_path):
    config = tmp_path / "sentinel.json"
    config.write_text('{"backup_sets": []}', encoding="utf-8")
    with pytest.raises(ConfigError):
        audit_config(config)


def test_cli_emits_json_and_returns_nonzero_for_error(tmp_path, capsys):
    config = tmp_path / "sentinel.json"
    write_config(config, tmp_path / "missing")

    exit_code = main([str(config), "--format", "json"])

    output = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert output["findings"][0]["rule_id"] == "backup-directory-missing"
