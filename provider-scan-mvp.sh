#!/usr/bin/env bash
# provider-scan-mvp.sh — companion evaluator for Snyk Code, Semgrep CI, and Socket Scan.
# It never changes Pi settings or package trees.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

: "${SNYK:=snyk}"
: "${SEMGREP:=semgrep}"
: "${SOCKET:=socket}"
: "${GIT:=git}"
: "${PYTHON3:=python3}"
: "${TIMEOUT_CMD:=timeout}"
: "${PROVIDER_TIMEOUT:=120}"
: "${TIMEOUT_GRACE:=5}"
: "${PI_AGENT_DIR:=$HOME/.pi/agent}"

CASE_ID=""
CANDIDATE_DIR=""
BASELINE_FILE=""
OUT_DIR=""
SNYK_ORG=""
ONLY=""
WORK_ROOT=""
CASE_DIR=""

usage() {
  cat <<'EOF'
Usage:
  provider-scan-mvp.sh \
    --case-id <safe-name> \
    --candidate-dir <copied-staged-candidate> \
    --baseline <existing-baseline.json> \
    --out-dir <output-directory> \
    [--snyk-org <org-id-or-slug>] \
    [--only snyk|semgrep|socket]

Evaluates authenticated, non-executing provider modes against a copied candidate.
It does not update or promote Pi extensions.
EOF
}

die() { printf 'FATAL: %s\n' "$*" >&2; exit 1; }
info() { printf '* %s\n' "$*" >&2; }

trash_path() {
  local path="$1"
  [ -e "$path" ] || return 0
  mkdir -p "$HOME/.Trash"
  mv "$path" "$HOME/.Trash/pi-provider-mvp-$(basename "$path")-$(date +%s)-$$" 2>/dev/null || true
}

cleanup() {
  if [ -n "$WORK_ROOT" ]; then
    trash_path "$WORK_ROOT"
  fi
  return 0
}
trap cleanup EXIT HUP INT TERM

require_absolute_file() {
  local label="$1" path="$2"
  [[ "$path" = /* ]] || die "$label path must be absolute: $path"
  [ -f "$path" ] || die "$label file not found: $path"
}

require_absolute_dir() {
  local label="$1" path="$2"
  [[ "$path" = /* ]] || die "$label path must be absolute: $path"
  [ -d "$path" ] || die "$label directory not found: $path"
}

validate_json() {
  "$PYTHON3" - "$1" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    json.load(f)
PY
}

# The input is untrusted. Reject symlinks so provider scanners cannot be led
# outside the private candidate copy through a candidate-controlled path.
copy_candidate() {
  local source="$1" destination="$2"
  "$PYTHON3" - "$source" "$destination" <<'PY'
import os, pathlib, shutil, sys
source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
for root, dirs, files in os.walk(source, followlinks=False):
    root_path = pathlib.Path(root)
    dirs[:] = [d for d in dirs if d != ".git"]
    for name in dirs + files:
        path = root_path / name
        if path.is_symlink():
            raise SystemExit(f"candidate contains symlink: {path}")
shutil.copytree(source, destination, ignore=shutil.ignore_patterns(".git"), copy_function=shutil.copy2)
PY
}

hash_tree() {
  "$PYTHON3" - "$1" <<'PY'
import hashlib, os, pathlib, sys
root = pathlib.Path(sys.argv[1])
h = hashlib.sha256()
for path in sorted((p for p in root.rglob("*") if p.is_file()), key=lambda p: p.relative_to(root).as_posix()):
    rel = path.relative_to(root).as_posix().encode("utf-8", "surrogateescape")
    h.update(len(rel).to_bytes(8, "big")); h.update(rel)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
print(h.hexdigest())
PY
}

scrub_file() {
  local path="$1"
  [ -f "$path" ] || return 0
  "$PYTHON3" - "$path" <<'PY'
import os, pathlib, sys
path = pathlib.Path(sys.argv[1])
try:
    text = path.read_text(encoding="utf-8", errors="replace")
except OSError:
    raise SystemExit(0)
for name in ("SNYK_TOKEN", "SEMGREP_APP_TOKEN", "SOCKET_SECURITY_API_KEY", "SOCKET_API_KEY"):
    value = os.environ.get(name)
    if value:
        text = text.replace(value, "[REDACTED]")
path.write_text(text, encoding="utf-8")
PY
}

redact_text() {
  "$PYTHON3" -c '
import os, sys
text = sys.stdin.read()
for name in ("SNYK_TOKEN", "SEMGREP_APP_TOKEN", "SOCKET_SECURITY_API_KEY", "SOCKET_API_KEY"):
    value = os.environ.get(name)
    if value:
        text = text.replace(value, "[REDACTED]")
sys.stdout.write(text)
'
}

command_version() {
  local command="$1"
  "$command" --version 2>/dev/null | head -n 1 | tr -d '\r' | redact_text || true
}

write_status() {
  local provider="$1" mode="$2" version="$3" started="$4" ended="$5" rc="$6" outcome="$7" stdout_name="$8" stderr_name="$9" native_name="${10}"
  "$PYTHON3" - "$CASE_DIR/$provider.status.json" "$provider" "$mode" "$version" "$started" "$ended" "$rc" "$outcome" "$stdout_name" "$stderr_name" "$native_name" <<'PY'
import json, sys
(path, provider, mode, version, started, ended, exit_code, outcome, stdout, stderr, native) = sys.argv[1:]
try:
    elapsed = max(0, int(ended) - int(started)) * 1000
except ValueError:
    elapsed = None
with open(path, "w", encoding="utf-8") as f:
    json.dump({
        "provider": provider,
        "command_mode": mode,
        "cli_version": version,
        "started_at_epoch": int(started),
        "ended_at_epoch": int(ended),
        "elapsed_ms": elapsed,
        "exit_code": int(exit_code),
        "outcome": outcome,
        "artifact_paths": [stdout, stderr, native],
    }, f, indent=2)
    f.write("\n")
PY
}

native_outcome() {
  local rc="$1" native="$2" provider="$3"
  if [ "$rc" -eq 124 ]; then
    printf 'error\n'
    return
  fi
  if [ ! -s "$native" ] || ! validate_json "$native" >/dev/null 2>&1; then
    printf 'error\n'
    return
  fi
  "$PYTHON3" - "$native" "$rc" "$provider" <<'PY'
import json, sys
path, rc, provider = sys.argv[1:]
try:
    data = json.load(open(path, encoding="utf-8"))
except Exception:
    print("error"); raise SystemExit
if provider == "semgrep" and data.get("errors"):
    print("error"); raise SystemExit
if int(rc) == 0:
    print("clean"); raise SystemExit
# Each selected provider reports findings with a non-zero status. A valid native
# result makes this distinguishable from a tool/authentication failure.
print("findings")
PY
}

selected() {
  [ -z "$ONLY" ] || [ "$ONLY" = "$1" ]
}

require_command() {
  local label="$1" command="$2"
  command -v "$command" >/dev/null 2>&1 || die "Required $label command not found: $command"
}

run_snyk() {
  local copy="$WORK_ROOT/snyk-candidate" native="$CASE_DIR/snyk-code.json"
  local stdout="$CASE_DIR/snyk.stdout" stderr="$CASE_DIR/snyk.stderr"
  local started ended rc=0 outcome version
  copy_candidate "$CANDIDATE_DIR" "$copy"
  version=$(command_version "$SNYK")
  started=$(date +%s)
  set +e
  if [ -n "$SNYK_ORG" ]; then
    (cd "$copy" && "$TIMEOUT_CMD" -k "$TIMEOUT_GRACE" "$PROVIDER_TIMEOUT" "$SNYK" code test --json-file-output="$native" --org="$SNYK_ORG") >"$stdout" 2>"$stderr"
  else
    (cd "$copy" && "$TIMEOUT_CMD" -k "$TIMEOUT_GRACE" "$PROVIDER_TIMEOUT" "$SNYK" code test --json-file-output="$native") >"$stdout" 2>"$stderr"
  fi
  rc=$?
  set -e
  ended=$(date +%s)
  scrub_file "$stdout"; scrub_file "$stderr"; scrub_file "$native"
  outcome=$(native_outcome "$rc" "$native" snyk)
  write_status snyk "snyk code test" "$version" "$started" "$ended" "$rc" "$outcome" "snyk.stdout" "snyk.stderr" "snyk-code.json"
  [ "$outcome" != error ]
}

prepare_semgrep_repo() {
  local copy="$1" hooks="$WORK_ROOT/semgrep-hooks"
  mkdir -p "$hooks"
  "$GIT" init -q "$copy" >/dev/null 2>&1
  "$GIT" -C "$copy" config core.hooksPath "$hooks" >/dev/null 2>&1
  "$GIT" -C "$copy" add --all >/dev/null 2>&1
  "$GIT" -C "$copy" -c user.name="provider-scan-mvp" -c user.email="provider-scan-mvp@invalid" commit --no-verify -qm "candidate snapshot" >/dev/null 2>&1
}

run_semgrep() {
  local copy="$WORK_ROOT/semgrep-candidate" native="$CASE_DIR/semgrep-ci.json"
  local stdout="$CASE_DIR/semgrep.stdout" stderr="$CASE_DIR/semgrep.stderr"
  local started ended rc=0 outcome version
  copy_candidate "$CANDIDATE_DIR" "$copy"
  started=$(date +%s)
  if ! prepare_semgrep_repo "$copy"; then
    ended=$(date +%s)
    printf 'Failed to initialize ephemeral Git repository.\n' > "$stderr"
    printf '{}' > "$native"
    write_status semgrep "semgrep ci" "$(command_version "$SEMGREP")" "$started" "$ended" 2 error "semgrep.stdout" "semgrep.stderr" "semgrep-ci.json"
    return 1
  fi
  version=$(command_version "$SEMGREP")
  set +e
  (cd "$copy" && "$TIMEOUT_CMD" -k "$TIMEOUT_GRACE" "$PROVIDER_TIMEOUT" "$SEMGREP" ci --json-output="$native") >"$stdout" 2>"$stderr"
  rc=$?
  set -e
  ended=$(date +%s)
  scrub_file "$stdout"; scrub_file "$stderr"; scrub_file "$native"
  outcome=$(native_outcome "$rc" "$native" semgrep)
  write_status semgrep "semgrep ci" "$version" "$started" "$ended" "$rc" "$outcome" "semgrep.stdout" "semgrep.stderr" "semgrep-ci.json"
  [ "$outcome" != error ]
}

run_socket() {
  local copy="$WORK_ROOT/socket-candidate" native="$CASE_DIR/socket.json"
  local stdout="$CASE_DIR/socket.stdout" stderr="$CASE_DIR/socket.stderr"
  local started ended rc=0 outcome version
  copy_candidate "$CANDIDATE_DIR" "$copy"
  version=$(command_version "$SOCKET")
  started=$(date +%s)
  set +e
  (cd "$copy" && "$TIMEOUT_CMD" -k "$TIMEOUT_GRACE" "$PROVIDER_TIMEOUT" "$SOCKET" scan create --tmp --no-set-as-alerts-page --no-interactive --report --json .) >"$stdout" 2>"$stderr"
  rc=$?
  set -e
  ended=$(date +%s)
  # Socket's native output is its stdout. Keep a separate copy so status paths
  # remain stable and comparison never needs to parse human terminal text.
  cp "$stdout" "$native" 2>/dev/null || true
  scrub_file "$stdout"; scrub_file "$stderr"; scrub_file "$native"
  outcome=$(native_outcome "$rc" "$native" socket)
  write_status socket "socket scan create" "$version" "$started" "$ended" "$rc" "$outcome" "socket.stdout" "socket.stderr" "socket.json"
  [ "$outcome" != error ]
}

write_comparison() {
  "$PYTHON3" - "$CASE_DIR" <<'PY'
import json, pathlib, sys
case = pathlib.Path(sys.argv[1])
baseline = json.load(open(case / "baseline.json", encoding="utf-8"))
statuses = []
for provider in ("snyk", "semgrep", "socket"):
    path = case / f"{provider}.status.json"
    if path.exists():
        statuses.append(json.load(open(path, encoding="utf-8")))
def location_text(result, provider):
    if provider == "snyk":
        loc = (result.get("locations") or [{}])[0].get("physicalLocation", {})
        file = loc.get("artifactLocation", {}).get("uri", "?")
        line = loc.get("region", {}).get("startLine", "?")
        rule = result.get("ruleId", "?")
        level = result.get("level", "?")
        message = result.get("message", {}).get("text", "")
        return level, rule, file, line, message
    loc = (result.get("locations") or [{}])[0]
    file = loc.get("path", "?")
    line = loc.get("start", {}).get("line", "?")
    extra = result.get("extra", {})
    return extra.get("severity", "?"), result.get("check_id", "?"), file, line, extra.get("message", "")

def provider_findings(provider, native_path):
    try:
        data = json.load(open(native_path, encoding="utf-8"))
    except Exception:
        return []
    if provider == "snyk":
        results = [r for run in data.get("runs", []) for r in run.get("results", [])]
    elif provider == "semgrep":
        results = data.get("results", [])
    else:
        return []
    return [location_text(r, provider) for r in results]

with open(case / "comparison.md", "w", encoding="utf-8") as out:
    out.write("# Provider comparison\n\n")
    out.write(f"**Status:** {'BLOCKED' if any(s['outcome'] == 'error' for s in statuses) else 'REVIEW REQUIRED'}\n\n")
    out.write("## Existing baseline\n\n")
    out.write(f"Baseline keys: {', '.join(sorted(baseline.keys())) or '(empty object)'}\n\n")
    out.write("## Run status\n\n| Provider | Mode | Outcome | Exit | Elapsed ms | Native evidence |\n|---|---|---:|---:|---:|---|\n")
    for status in statuses:
        native = case / status["artifact_paths"][-1]
        out.write(f"| {status['provider']} | {status['command_mode']} | {status['outcome']} | {status['exit_code']} | {status['elapsed_ms']} | `{native.name}` |\n")
    out.write("\n## Findings requiring coding-agent triage\n\n")
    emitted = False
    for status in statuses:
        native = case / status["artifact_paths"][-1]
        findings = provider_findings(status["provider"], native)
        if not findings:
            continue
        emitted = True
        out.write(f"### {status['provider'].title()} ({len(findings)} alerts)\n\n")
        for level, rule, file, line, message in findings:
            out.write(f"- **{level}** `{rule}` — `{file}:{line}` — {message}\n")
        out.write("\n")
    if not emitted:
        out.write("No structured findings were available. Check provider status and raw artifacts.\n\n")
    out.write("## Triage requirements\n\n")
    out.write("- Confirmed vulnerabilities or unresolved provider errors block promotion.\n")
    out.write("- The coding agent must classify each alert as confirmed, false positive, pre-existing, introduced, or accepted risk.\n")
    out.write("- Uploaded-data scope: Snyk Code/Semgrep receive source analysis data; Socket receives dependency manifests.\n")
    out.write("- Socket `--tmp` retention: confirm separately before relying on deletion.\n")
PY
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --case-id) [ "$#" -ge 2 ] || die "--case-id requires a value"; CASE_ID="$2"; shift 2 ;;
      --candidate-dir) [ "$#" -ge 2 ] || die "--candidate-dir requires a value"; CANDIDATE_DIR="$2"; shift 2 ;;
      --baseline) [ "$#" -ge 2 ] || die "--baseline requires a value"; BASELINE_FILE="$2"; shift 2 ;;
      --out-dir) [ "$#" -ge 2 ] || die "--out-dir requires a value"; OUT_DIR="$2"; shift 2 ;;
      --snyk-org) [ "$#" -ge 2 ] || die "--snyk-org requires a value"; SNYK_ORG="$2"; shift 2 ;;
      --only) [ "$#" -ge 2 ] || die "--only requires a value"; ONLY="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown argument: $1" ;;
    esac
  done
}

main() {
  parse_args "$@"
  [ -n "$CASE_ID" ] || die "--case-id is required"
  [ -n "$CANDIDATE_DIR" ] || die "--candidate-dir is required"
  [ -n "$BASELINE_FILE" ] || die "--baseline is required"
  [ -n "$OUT_DIR" ] || die "--out-dir is required"
  [[ "$CASE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$ ]] || die "Unsafe case-id: $CASE_ID"
  [ -z "$ONLY" ] || [[ "$ONLY" =~ ^(snyk|semgrep|socket)$ ]] || die "--only must be snyk, semgrep, or socket"
  [[ "$OUT_DIR" = /* ]] || die "--out-dir must be absolute: $OUT_DIR"
  require_absolute_dir candidate "$CANDIDATE_DIR"
  require_absolute_file baseline "$BASELINE_FILE"
  validate_json "$BASELINE_FILE" >/dev/null 2>&1 || die "Baseline is not valid JSON: $BASELINE_FILE"

  local candidate_real agent_real
  candidate_real=$("$PYTHON3" -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$CANDIDATE_DIR")
  agent_real=$("$PYTHON3" -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$PI_AGENT_DIR")
  case "$candidate_real" in
    "$agent_real"/node_modules/*|"$agent_real"/npm/node_modules/*) die "Candidate must be a copy, not a live Pi package directory" ;;
  esac

  mkdir -p "$OUT_DIR"
  CASE_DIR="$OUT_DIR/$CASE_ID"
  [ ! -e "$CASE_DIR" ] || die "Case output already exists: $CASE_DIR"
  umask 077
  mkdir -p "$CASE_DIR"
  cp "$BASELINE_FILE" "$CASE_DIR/baseline.json"
  hash_tree "$CANDIDATE_DIR" > "$CASE_DIR/input-before.sha256"
  WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/pi-provider-mvp.XXXXXX")

  if selected snyk; then require_command snyk "$SNYK"; fi
  if selected semgrep; then require_command semgrep "$SEMGREP"; require_command git "$GIT"; fi
  if selected socket; then require_command socket "$SOCKET"; fi
  require_command python3 "$PYTHON3"
  require_command timeout "$TIMEOUT_CMD"

  local failed=0
  if selected snyk; then info "Running Snyk Code"; run_snyk || failed=1; fi
  if selected semgrep; then info "Running Semgrep CI"; run_semgrep || failed=1; fi
  if selected socket; then info "Running Socket Scan"; run_socket || failed=1; fi

  hash_tree "$CANDIDATE_DIR" > "$CASE_DIR/input-after.sha256"
  cmp -s "$CASE_DIR/input-before.sha256" "$CASE_DIR/input-after.sha256" || { failed=1; printf 'Candidate changed while scanning.\n' > "$CASE_DIR/input-integrity-error.txt"; }
  write_comparison

  if [ "$failed" -ne 0 ]; then
    die "One or more requested provider scans had an error; see $CASE_DIR"
  fi
  info "Provider MVP completed: $CASE_DIR"
}

main "$@"
