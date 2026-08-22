# pi-safe-update

A local security gate for updating Pi extensions and packages.

`pi-safe-update` stages one candidate in an isolated Pi directory, checks the candidate for malware and backdoors, runs a constrained startup smoke test, and promotes it only when the required checks pass. It is designed for Pi installations on macOS.

This tool is a security review and containment workflow. It is not proof that a package is safe, and it is not a general-purpose package manager.

## What it checks

- Changes are limited to the selected package and its reviewed dependency trees.
- npm lifecycle scripts are disabled during staging.
- Package contents, executable files, binaries, hidden code, obfuscation, dependency metadata, and suspicious runtime capabilities are reviewed.
- npm signatures and OSV-Scanner results are collected when applicable.
- An optional provider evaluator can run Snyk, Semgrep, and Socket scans.
- The candidate starts in an offline macOS sandbox with no live credentials.
- A read-only security review receives bounded candidate evidence.

Normal capabilities such as filesystem, network, process, or executable access are review signals. They are not malware findings by themselves.

## Requirements

- macOS with `sandbox-exec`
- Pi CLI
- Bash
- Python 3
- npm
- Git
- ripgrep (`rg`)
- OSV-Scanner
- a compatible `timeout` command

Optional provider scans use locally authenticated `snyk`, `semgrep`, and `socket` CLIs. Provider credentials are never stored in this repository or passed as command-line arguments.

## Install

Clone the repository outside the Pi profile you want to protect:

```bash
git clone https://github.com/selimerunkut/pi-safe-update-public.git
cd pi-safe-update-public
```

The updater reads the Pi package list from:

```text
$PI_AGENT_DIR/settings.json
```

By default, `PI_AGENT_DIR` is `~/.pi/agent`. The package entries must be string-form npm packages or GitHub packages pinned to a full commit SHA.

Before the first real update, inspect the command and run the local tests:

```bash
./pi-safe-update.sh help
python3 -m unittest discover -s tests -p 'test_*.py'
bash tests/test-pi-safe-update.sh
bash tests/test-provider-scan-mvp.sh
```

## Usage

Check every configured npm package and update outdated candidates sequentially:

```bash
./pi-safe-update.sh update-all
```

Review one package:

```bash
./pi-safe-update.sh update <package-or-configured-source> --to latest
./pi-safe-update.sh update <package-or-configured-source> --to <exact-version>
```

GitHub sources must use a full 40-character commit SHA:

```bash
./pi-safe-update.sh update github:owner/repository#<40-hex-sha>
```

A blocked candidate is left unchanged. Read its retained security report before investigating further. Do not bypass a security result or manually copy a candidate into the live Pi profile.

## Configuration

The updater uses environment variables for optional path and tool overrides. See [`examples/environment.example`](examples/environment.example) for a safe template. The updater does not load environment files automatically; source the template explicitly when needed.

| Variable | Default | Purpose |
| --- | --- | --- |
| `PI_AGENT_DIR` | `$HOME/.pi/agent` | Pi profile to protect |
| `PROVIDER_SCANS` | `auto` | `auto` or `off` |
| `PROVIDER_SCAN_ONLY` | empty | Limit provider scans to `snyk`, `semgrep`, or `socket` |
| `PROVIDER_TIMEOUT` | `120` | Provider timeout in seconds |
| `SECURITY_TIMEOUT` | `300` | Shared security-phase timeout in seconds |
| `SMOKE_TIMEOUT` | `30` | Candidate smoke-test timeout in seconds |
| `STAGING_TIMEOUT` | `300` | Isolated staging timeout in seconds |
| `PI`, `NPM`, `GIT`, `PYTHON3`, `TIMEOUT_CMD`, `SANDBOX_EXEC`, `RG`, `OSV_SCANNER` | system command | Override a tool executable |
| `LOCK_DIR` | `$PI_AGENT_DIR/.pi-safe-update` | Lock and retained-run directory |

Keep provider authentication in the provider CLI's supported credential store or a secret manager. Never put tokens in `.env`, settings files, artifacts, or commit history.

## Evidence and failure behavior

Run evidence is retained under:

```text
$LOCK_DIR/runs/<run-id>/artifacts/
```

`update-all` also writes a batch summary under:

```text
$LOCK_DIR/runs/batches/<batch-id>/summary.md
```

A confirmed malware or backdoor finding blocks promotion. Provider outages, malformed provider output, and review timeouts are retained as `UNVERIFIED` evidence rather than being treated as malware. A same-process promotion failure stops that update and attempts to restore the live state; it is not a malware verdict.

This project deliberately does not provide a rollback command or persistent package backups. Keep your normal Pi configuration backups independently. An interrupted filesystem operation should be investigated from the retained run artifacts before retrying.

## Development

The public shell entrypoint is a compatibility wrapper. The implementation is in `pi_safe_update/`. Provider scanning is optional and implemented by `provider-scan-mvp.sh`.

Run the complete local validation suite:

```bash
bash -n pi-safe-update.sh provider-scan-mvp.sh
python3 -m py_compile pi_safe_update/*.py
python3 -m unittest discover -s tests -p 'test_*.py'
bash tests/test-pi-safe-update.sh
bash tests/test-provider-scan-mvp.sh
git diff --check
```

The tests use local command shims. They do not access the network, the real Pi profile, or candidate package code.

## Security boundary

Static analysis and a constrained startup test reduce risk but cannot prove that a package is benign. The package manager still processes untrusted metadata and archives during isolated staging. Review the source, target version, retained artifacts, and local changes before approving updates.

See [`docs/`](docs/) for the detailed workflow and provider-scanning design.

## License

MIT. See [`LICENSE`](LICENSE).
