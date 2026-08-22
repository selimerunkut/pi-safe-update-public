#!/usr/bin/env bash
# Local-only tests for provider-scan-mvp.sh. No network, login, Docker, or candidate execution.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
HARNESS="$PROJECT_DIR/provider-scan-mvp.sh"
PASS=0
FAIL=0
TEST_TEMP=""

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; }

trash_test() {
  [ -n "${TEST_TEMP:-}" ] || return 0
  [ -e "$TEST_TEMP" ] || return 0
  mkdir -p "$HOME/.Trash"
  mv "$TEST_TEMP" "$HOME/.Trash/pi-provider-mvp-test-$(basename "$TEST_TEMP")-$(date +%s)-$$" 2>/dev/null || true
}

setup() {
  TEST_TEMP=$(mktemp -d "${TMPDIR:-/tmp}/pi-provider-mvp-test.XXXXXX")
  SHIMS="$TEST_TEMP/shims"
  CANDIDATE="$TEST_TEMP/candidate"
  BASELINE="$TEST_TEMP/baseline.json"
  OUT="$TEST_TEMP/out"
  AGENT="$TEST_TEMP/pi-agent"
  LOG="$TEST_TEMP/invocations.log"
  mkdir -p "$SHIMS" "$CANDIDATE/.git" "$AGENT/node_modules/live-pkg"
  printf 'candidate source\n' > "$CANDIDATE/index.js"
  printf '{"name":"candidate","version":"1.0.0"}\n' > "$CANDIDATE/package.json"
  printf 'must-not-be-copied\n' > "$CANDIDATE/.git/source-secret"
  printf '{"schema":1,"findings":[],"expected_findings":[]}\n' > "$BASELINE"
  : > "$LOG"
  make_shims
}

teardown() { trash_test; TEST_TEMP=""; }

make_shims() {
  cat > "$SHIMS/snyk" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
echo "snyk $*" >> "$FAKE_LOG"
json=""
for arg in "$@"; do case "$arg" in --json-file-output=*) json="${arg#*=}";; esac; done
printf '%s\n' "${SNYK_TOKEN:-}"
if [ "${FAKE_SNYK_NO_JSON:-0}" != 1 ]; then
  printf '{"issues":[],"token":"%s"}\n' "${SNYK_TOKEN:-}" > "$json"
fi
exit "${FAKE_SNYK_RC:-0}"
SHIM
  cat > "$SHIMS/semgrep" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
echo "semgrep $* cwd=$PWD" >> "$FAKE_LOG"
[ ! -f "$PWD/.git/source-secret" ] || exit 98
json=""
for arg in "$@"; do case "$arg" in --json-output=*) json="${arg#*=}";; esac; done
printf '%s\n' "${SEMGREP_APP_TOKEN:-}"
if [ "${FAKE_SEMGREP_NO_JSON:-0}" != 1 ]; then
  printf '{"results":[],"errors":[],"token":"%s"}\n' "${SEMGREP_APP_TOKEN:-}" > "$json"
fi
exit "${FAKE_SEMGREP_RC:-0}"
SHIM
  cat > "$SHIMS/socket" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
echo "socket $*" >> "$FAKE_LOG"
printf '{"healthy":true,"token":"%s"}\n' "${SOCKET_SECURITY_API_KEY:-}"
exit "${FAKE_SOCKET_RC:-0}"
SHIM
  cat > "$SHIMS/git" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
echo "git $*" >> "$FAKE_LOG"
if [ "${1:-}" = init ]; then
  last="${!#}"
  mkdir -p "$last/.git"
fi
exit "${FAKE_GIT_RC:-0}"
SHIM
  cat > "$SHIMS/timeout" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
echo "timeout $*" >> "$FAKE_LOG"
if [ "${FAKE_TIMEOUT:-0}" = 1 ]; then exit 124; fi
if [ "${1:-}" = -k ]; then shift 2; fi
shift
exec "$@"
SHIM
  chmod +x "$SHIMS"/*
}

run_harness() {
  local case_id="$1"; shift
  set +e
  (
    export PATH="$SHIMS:$PATH"
    export FAKE_LOG="$LOG"
    export SNYK="$SHIMS/snyk" SEMGREP="$SHIMS/semgrep" SOCKET="$SHIMS/socket" GIT="$SHIMS/git" TIMEOUT_CMD="$SHIMS/timeout"
    export PI_AGENT_DIR="$AGENT"
    local override
    for override in "$@"; do export "$override"; done
    if [ -n "${HARNESS_ONLY:-}" ]; then
      "$HARNESS" --case-id "$case_id" --candidate-dir "$CANDIDATE" --baseline "$BASELINE" --out-dir "$OUT" --only "$HARNESS_ONLY"
    else
      "$HARNESS" --case-id "$case_id" --candidate-dir "$CANDIDATE" --baseline "$BASELINE" --out-dir "$OUT"
    fi
  ) >"$TEST_TEMP/stdout" 2>"$TEST_TEMP/stderr"
  RUN_RC=$?
  set -e
}

status_outcome() {
  python3 - "$OUT/$1/$2.status.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))["outcome"])
PY
}

contains() { grep -q -- "$1" "$2"; }

assert_true() {
  local description="$1"; shift
  if "$@"; then pass "$description"; else fail "$description"; fi
}

test_happy_path() {
  setup
  run_harness happy
  assert_true "all-provider run succeeds" test "$RUN_RC" -eq 0
  assert_true "baseline copied" test -f "$OUT/happy/baseline.json"
  assert_true "all status files retained" test -f "$OUT/happy/snyk.status.json" -a -f "$OUT/happy/semgrep.status.json" -a -f "$OUT/happy/socket.status.json"
  assert_true "Snyk command invoked" contains 'snyk code test' "$LOG"
  assert_true "Semgrep command invoked" contains 'semgrep ci' "$LOG"
  assert_true "Socket command invoked" contains 'socket scan create --tmp --no-set-as-alerts-page --no-interactive --report --json .' "$LOG"
  assert_true "prohibited provider options absent" bash -c "! grep -Eq -- '--allow-local-builds|--allow-untrusted-validators|--reach|--auto-manifest' '$LOG'"
  assert_true "Semgrep configures disabled hooks" contains 'config core.hooksPath' "$LOG"
  assert_true "Semgrep source .git is excluded" bash -c "! grep -q 'source-secret' '$TEST_TEMP/stderr'"
  assert_true "input hash remains unchanged" cmp -s "$OUT/happy/input-before.sha256" "$OUT/happy/input-after.sha256"
  teardown
}

test_snyk_findings_are_not_tool_error() {
  setup
  run_harness snyk-findings FAKE_SNYK_RC=1 HARNESS_ONLY=snyk
  assert_true "Snyk findings exit is successful harness result" test "$RUN_RC" -eq 0
  assert_true "Snyk exit 1 is findings" test "$(status_outcome snyk-findings snyk)" = findings
  teardown
}

test_missing_native_json_is_error() {
  setup
  run_harness missing-json FAKE_SNYK_NO_JSON=1 HARNESS_ONLY=snyk
  assert_true "missing JSON exits non-zero" test "$RUN_RC" -ne 0
  assert_true "missing JSON is error" test "$(status_outcome missing-json snyk)" = error
  teardown
}

test_timeout_is_error() {
  setup
  run_harness timeout FAKE_TIMEOUT=1 HARNESS_ONLY=socket
  assert_true "timeout exits non-zero" test "$RUN_RC" -ne 0
  assert_true "timeout recorded as error" test "$(status_outcome timeout socket)" = error
  assert_true "timeout uses configured grace period" contains 'timeout -k 5 120' "$LOG"
  teardown
}

test_continues_after_provider_error() {
  setup
  run_harness continued FAKE_SNYK_NO_JSON=1
  assert_true "provider error exits non-zero after complete run" test "$RUN_RC" -ne 0
  assert_true "Socket still runs after Snyk error" contains 'socket scan create' "$LOG"
  teardown
}

test_only_missing_cli_is_not_clean() {
  setup
  set +e
  PATH="$SHIMS:$PATH" FAKE_LOG="$LOG" SNYK="$SHIMS/snyk" SEMGREP="$TEST_TEMP/missing-semgrep" SOCKET="$SHIMS/socket" GIT="$SHIMS/git" TIMEOUT_CMD="$SHIMS/timeout" PI_AGENT_DIR="$AGENT" \
    "$HARNESS" --only semgrep --case-id only-missing --candidate-dir "$CANDIDATE" --baseline "$BASELINE" --out-dir "$OUT" >"$TEST_TEMP/stdout" 2>"$TEST_TEMP/stderr"
  RUN_RC=$?
  set -e
  assert_true "--only missing Semgrep exits non-zero" test "$RUN_RC" -ne 0
  assert_true "--only missing Semgrep is not reported clean" bash -c "! grep -qi 'completed' '$TEST_TEMP/stderr'"
  teardown
}

test_tokens_are_scrubbed() {
  setup
  run_harness tokens SNYK_TOKEN=fixture-token-value SEMGREP_APP_TOKEN=fixture-token-value SOCKET_SECURITY_API_KEY=fixture-token-value
  assert_true "token-containing provider outputs are scrubbed" bash -c "! grep -R -q -- 'fixture-token-value' '$OUT/tokens'"
  teardown
}

test_live_package_path_rejected() {
  setup
  set +e
  PATH="$SHIMS:$PATH" FAKE_LOG="$LOG" SNYK="$SHIMS/snyk" SEMGREP="$SHIMS/semgrep" SOCKET="$SHIMS/socket" GIT="$SHIMS/git" TIMEOUT_CMD="$SHIMS/timeout" PI_AGENT_DIR="$AGENT" \
    "$HARNESS" --only snyk --case-id live-rejected --candidate-dir "$AGENT/node_modules/live-pkg" --baseline "$BASELINE" --out-dir "$OUT" >"$TEST_TEMP/stdout" 2>"$TEST_TEMP/stderr"
  RUN_RC=$?
  set -e
  assert_true "live Pi package path rejected" test "$RUN_RC" -ne 0
  assert_true "live rejection explains copy requirement" contains 'must be a copy' "$TEST_TEMP/stderr"
  teardown
}

printf 'provider-scan-mvp test suite\n\n'
test_happy_path
test_snyk_findings_are_not_tool_error
test_missing_native_json_is_error
test_timeout_is_error
test_continues_after_provider_error
test_only_missing_cli_is_not_clean
test_tokens_are_scrubbed
test_live_package_path_rejected
printf '\nTests passed: %s | failed: %s\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
