# Backup Sentinel

Backup Sentinel is a read-only command-line audit for scheduled backup folders. It checks whether expected backup files exist, whether the newest file is within an age limit, and optionally whether each file matches its adjacent SHA-256 sidecar.

It is designed for small teams and server owners who need a simple, scriptable check that backup jobs are still producing files and that stored copies have not changed since their checksums were written.

## Features

- Audit multiple named backup sets from one JSON configuration.
- Match files using glob patterns and enforce minimum file counts.
- Report when the newest matching backup exceeds a configured age.
- Warn on a backup timestamp more than five minutes in the future.
- Optionally verify adjacent `<backup>.sha256` files.
- Emit human-readable or JSON reports with stable exit codes.
- Read-only behavior: it never deletes, moves, rewrites, or repairs backups.
- Skips symbolic-link files and rejects symbolic-link roots.

## Install and run

```shell
python -m venv .venv
# Activate the environment, then:
python -m pip install --require-hashes -r requirements-dev.lock
python -m pip install --no-deps --no-build-isolation -e .
copy backup-sentinel.example.json backup-sentinel.json
backup-sentinel backup-sentinel.json
```

Relative backup paths are resolved against the configuration file's directory. Add `--format json` for monitoring integrations or `--fail-on warning` to make warnings fail the command. Exit status `0` means no finding met the chosen threshold, `1` means a finding met it, and `2` means configuration could not be read or validated.

## SHA-256 sidecars

When `verify_sidecars` is true, each selected backup needs an adjacent file named `<backup-name>.sha256`. The first whitespace-separated token must be a 64-character SHA-256 digest; the usual `sha256sum` format is accepted.

Example configuration:

```json
{
  "backup_sets": [
    {
      "name": "nightly-database",
      "path": "./backups/database",
      "include": ["*.sql.gz"],
      "max_age_hours": 26,
      "minimum_files": 1,
      "verify_sidecars": true
    }
  ]
}
```

## Tests

```shell
python -m pytest -q
```

GitHub Actions runs the tests on Python 3.11 and 3.12.

## Limitations

- A matching checksum only proves the backup matches its sidecar. Store manifests separately or sign them to detect an attacker who can rewrite both.
- The tool does not prove that a database or archive can be restored. Regular restore drills remain necessary.
- It does not connect to cloud object storage, backup agents, or monitoring platforms.
- No license is included pending the owner's license choice.
