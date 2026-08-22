#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$repo_root"

targets=("$@")
if [ "${#targets[@]}" -eq 0 ]; then
  targets=(".")
fi

rg_base=(
  --hidden
  --follow
  --line-number
  --no-heading
  --color never
  --glob '!**/.git/**'
  --glob '!**/node_modules/**'
  --glob '!**/dist/**'
  --glob '!**/build/**'
  --glob '!**/coverage/**'
  --glob '!**/.next/**'
  --glob '!**/.turbo/**'
  --glob '!**/*.md'
  --glob '!**/*.mdx'
  --glob '!**/*.lock'
  --glob '!**/scripts/hidden-code-scan.sh'
  --glob '!**/tests/hidden-code-scan.test.sh'
)

scan_pattern() {
  local label="$1"
  local pattern="$2"
  local mode="${3:-basic}"
  local files=()

  printf '\n== %s ==\n' "$label"
  if [ "$mode" = "pcre" ]; then
    if ! output="$(rg -nP "${rg_base[@]}" "$pattern" "${targets[@]}" 2>/dev/null)"; then
      output=""
    fi
  else
    if ! output="$(rg -n "${rg_base[@]}" "$pattern" "${targets[@]}" 2>/dev/null)"; then
      output=""
    fi
  fi

  if [ -n "$output" ]; then
    printf '%s\n' "$output"
    return 1
  fi

  printf 'No matches.\n'
}

status=0

scan_pattern \
  "Long whitespace followed by code" \
  '[[:blank:]]{60,}\S' \
  pcre || status=1

scan_pattern \
  "Invisible or control Unicode" \
  '[\p{Cf}\x00-\x08\x0B\x0C\x0E-\x1F\x7F]' \
  pcre || status=1

scan_pattern \
  "Suspicious JS execution primitives" \
  '\b(eval|new[[:space:]]+Function|child_process|execSync|spawnSync|spawn[[:space:]]*\(|exec[[:space:]]*\(|fetch[[:space:]]*\(|XMLHttpRequest|atob[[:space:]]*\()' \
  pcre || status=1

scan_pattern \
  "Suspicious base64 decode literals" \
  'Buffer\.from\([[:space:]]*["'\''][A-Za-z0-9+/=]{40,}["'\''][[:space:]]*,[[:space:]]*["'\'']base64["'\'']' \
  pcre || status=1

exit "$status"
