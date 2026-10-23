#!/usr/bin/env bash
set -euo pipefail

# emudhra-checker — verify whether this system is affected by the eMudhra CA compromise
# Usage: ./check.sh [--json]

JSON_MODE=false
[ "${1:-}" = "--json" ] && JSON_MODE=true

# --- colors ---
if [ -t 1 ] && [ "$JSON_MODE" = false ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BOLD='\033[1m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BOLD=''; NC=''
fi

PASS=0; FAIL=0; WARN=0
declare -a JSON_RESULTS=()

log_pass() {
  PASS=$((PASS+1))
  if [ "$JSON_MODE" = true ]; then
    JSON_RESULTS+=("{\"check\":\"$1\",\"status\":\"pass\",\"detail\":\"$2\"}")
  else
    echo -e "  ${GREEN}[PASS]${NC} $1: $2"
  fi
}

log_fail() {
  FAIL=$((FAIL+1))
  if [ "$JSON_MODE" = true ]; then
    JSON_RESULTS+=("{\"check\":\"$1\",\"status\":\"fail\",\"detail\":\"$2\"}")
  else
    echo -e "  ${RED}[FAIL]${NC} $1: $2"
  fi
}

log_warn() {
  WARN=$((WARN+1))
  if [ "$JSON_MODE" = true ]; then
    JSON_RESULTS+=("{\"check\":\"$1\",\"status\":\"warn\",\"detail\":\"$2\"}")
  else
    echo -e "  ${YELLOW}[WARN]${NC} $1: $2"
  fi
}

log_info() {
  if [ "$JSON_MODE" = true ]; then
    JSON_RESULTS+=("{\"check\":\"$1\",\"status\":\"info\",\"detail\":\"$2\"}")
  else
    echo -e "  [INFO] $1: $2"
  fi
}

[ "$JSON_MODE" = false ] && echo -e "${BOLD}emudhra-checker — eMudhra CA compromise verification${NC}"
[ "$JSON_MODE" = false ] && echo ""

# --- 1. system CA bundle ---
[ "$JSON_MODE" = false ] && echo -e "${BOLD}System CA Bundle${NC}"

CA_FILE=""
for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem /usr/local/share/certs/ca-root-nss.crt; do
  [ -f "$f" ] && CA_FILE="$f" && break
done

if [ -n "$CA_FILE" ]; then
  EMSIGN_COUNT=$(grep -c "emSign" "$CA_FILE" 2>/dev/null || echo 0)
  if [ "$EMSIGN_COUNT" -gt 0 ]; then
    ROOTS=$(grep "emSign" "$CA_FILE" 2>/dev/null | tr '\n' ', ' | sed 's/,$//')
    log_fail "emSign in CA bundle" "$EMSIGN_COUNT entries found: $ROOTS"
  else
    log_pass "emSign in CA bundle" "no emSign entries found"
  fi
else
  # macOS: check keychain
  if command -v security &>/dev/null; then
    MACOS_EMSIGN=$(security find-certificate -a -Z /System/Library/Keychains/SystemRootCertificates.keychain 2>/dev/null | grep -c "emSign" || echo 0)
    if [ "$MACOS_EMSIGN" -gt 0 ]; then
      log_fail "emSign in keychain" "$MACOS_EMSIGN entries found"
    else
      log_pass "emSign in keychain" "no emSign entries found"
    fi
  else
    log_warn "CA bundle" "could not locate system CA bundle"
  fi
fi

# --- 2. ca-certificates package ---
[ "$JSON_MODE" = false ] && echo -e "\n${BOLD}CA Certificates Package${NC}"

if command -v dpkg &>/dev/null; then
  PKG_VER=$(dpkg -l ca-certificates 2>/dev/null | awk '/^ii/{print $3}' || echo "not-installed")
  if [ "$PKG_VER" = "not-installed" ]; then
    log_warn "ca-certificates (dpkg)" "not installed"
  else
    log_info "ca-certificates (dpkg)" "$PKG_VER"
    case "$PKG_VER" in
      *20260816*|*20261020*|*20250419~deb12u2*|*20250419+deb13u1*) log_pass "ca-certificates version" "patched ($PKG_VER)" ;;
      *) log_warn "ca-certificates version" "may be outdated ($PKG_VER) — check against distro fixed version" ;;
    esac
  fi
elif command -v rpm &>/dev/null; then
  PKG_VER=$(rpm -q ca-certificates 2>/dev/null || echo "not-installed")
  log_info "ca-certificates (rpm)" "$PKG_VER"
elif command -v apk &>/dev/null; then
  PKG_VER=$(apk info ca-certificates 2>/dev/null | head -1 || echo "not-installed")
  log_info "ca-certificates (apk)" "$PKG_VER"
elif [ "$(uname)" = "Darwin" ]; then
  log_info "ca-certificates" "macOS uses system keychain (managed by Apple security updates)"
fi

# --- 3. Go version ---
[ "$JSON_MODE" = false ] && echo -e "\n${BOLD}Go${NC}"

if command -v go &>/dev/null; then
  GO_VER=$(go version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  GO_MAJOR=$(echo "$GO_VER" | cut -d. -f1)
  GO_MINOR=$(echo "$GO_VER" | cut -d. -f2)
  GO_PATCH=$(echo "$GO_VER" | cut -d. -f3)

  if [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -eq 26 ] && [ "$GO_PATCH" -ge 10 ]; then
    log_pass "Go" "$GO_VER (>= 1.26.10, has SPKI denylist)"
  elif [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -eq 27 ] && [ "$GO_PATCH" -ge 3 ]; then
    log_pass "Go" "$GO_VER (>= 1.27.3, has SPKI denylist)"
  elif [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -ge 28 ]; then
    log_pass "Go" "$GO_VER (>= 1.28, has SPKI denylist)"
  else
    log_fail "Go" "$GO_VER — needs >= 1.26.10 or >= 1.27.3 for CVE-2026-111943 fix"
  fi
else
  log_info "Go" "not installed"
fi

# --- 4. Node.js version ---
[ "$JSON_MODE" = false ] && echo -e "\n${BOLD}Node.js${NC}"

if command -v node &>/dev/null; then
  NODE_VER=$(node --version 2>/dev/null | sed 's/^v//')
  NODE_MAJOR=$(echo "$NODE_VER" | cut -d. -f1)
  NODE_MINOR=$(echo "$NODE_VER" | cut -d. -f2)
  NODE_PATCH=$(echo "$NODE_VER" | cut -d. -f3)

  FIXED=false
  if [ "$NODE_MAJOR" -eq 22 ] && { [ "$NODE_MINOR" -gt 23 ] || { [ "$NODE_MINOR" -eq 23 ] && [ "$NODE_PATCH" -ge 4 ]; }; }; then FIXED=true; fi
  if [ "$NODE_MAJOR" -eq 24 ] && { [ "$NODE_MINOR" -gt 22 ] || { [ "$NODE_MINOR" -eq 22 ] && [ "$NODE_PATCH" -ge 1 ]; }; }; then FIXED=true; fi
  if [ "$NODE_MAJOR" -eq 26 ] && { [ "$NODE_MINOR" -gt 12 ] || { [ "$NODE_MINOR" -eq 12 ] && [ "$NODE_PATCH" -ge 1 ]; }; }; then FIXED=true; fi
  if [ "$NODE_MAJOR" -gt 26 ]; then FIXED=true; fi

  if [ "$FIXED" = true ]; then
    log_pass "Node.js" "$NODE_VER (patched)"
  else
    log_fail "Node.js" "$NODE_VER — needs >= 22.23.4 / 24.22.1 / 26.12.1"
  fi
else
  log_info "Node.js" "not installed"
fi

# --- 5. Python certifi ---
[ "$JSON_MODE" = false ] && echo -e "\n${BOLD}Python certifi${NC}"

if command -v python3 &>/dev/null; then
  CERTIFI_VER=$(python3 -c "import certifi; print(certifi.__version__)" 2>/dev/null || echo "not-installed")
  if [ "$CERTIFI_VER" = "not-installed" ]; then
    log_info "Python certifi" "not installed"
  else
    if python3 -c "
from packaging.version import Version
import sys
try:
    v = Version('$CERTIFI_VER')
    sys.exit(0 if v >= Version('2026.10.19') else 1)
except:
    sys.exit(1)
" 2>/dev/null; then
      log_pass "Python certifi" "$CERTIFI_VER (>= 2026.10.19)"
    else
      # fallback: simple string comparison
      if [ "$CERTIFI_VER" \> "2026.10.18" ] 2>/dev/null; then
        log_pass "Python certifi" "$CERTIFI_VER (>= 2026.10.19)"
      else
        log_fail "Python certifi" "$CERTIFI_VER — needs >= 2026.10.19"
      fi
    fi
  fi
else
  log_info "Python" "python3 not found"
fi

# --- 6. Rust webpki-roots ---
[ "$JSON_MODE" = false ] && echo -e "\n${BOLD}Rust webpki-roots${NC}"

CARGO_LOCKS=$(find . -maxdepth 5 -name "Cargo.lock" 2>/dev/null | head -10)
if [ -n "$CARGO_LOCKS" ]; then
  for lockfile in $CARGO_LOCKS; do
    WPR_VER=$(grep -A1 'name = "webpki-roots"' "$lockfile" 2>/dev/null | grep 'version' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "")
    if [ -n "$WPR_VER" ]; then
      WPR_MAJOR=$(echo "$WPR_VER" | cut -d. -f1)
      WPR_MINOR=$(echo "$WPR_VER" | cut -d. -f2)
      WPR_PATCH=$(echo "$WPR_VER" | cut -d. -f3)
      if { [ "$WPR_MAJOR" -eq 1 ] && [ "$WPR_MINOR" -eq 0 ] && [ "$WPR_PATCH" -ge 10 ]; } || \
         { [ "$WPR_MAJOR" -eq 0 ] && [ "$WPR_MINOR" -eq 26 ] && [ "$WPR_PATCH" -ge 11 ]; }; then
        log_pass "webpki-roots ($lockfile)" "$WPR_VER"
      else
        log_fail "webpki-roots ($lockfile)" "$WPR_VER — needs >= 1.0.10 or >= 0.26.11"
      fi
    fi
  done
else
  log_info "Rust webpki-roots" "no Cargo.lock files found"
fi

# --- 7. OpenSSL / curl ---
[ "$JSON_MODE" = false ] && echo -e "\n${BOLD}OpenSSL / curl${NC}"

if command -v openssl &>/dev/null; then
  log_info "OpenSSL" "$(openssl version 2>/dev/null)"
fi
if command -v curl &>/dev/null; then
  log_info "curl" "$(curl --version 2>/dev/null | head -1)"
fi

# --- 8. TLS live tests ---
[ "$JSON_MODE" = false ] && echo -e "\n${BOLD}TLS Live Tests${NC}"

if command -v curl &>/dev/null; then
  # emSign direct chain (should be REJECTED after fix)
  RESULT=$(curl -sS --max-time 15 -o /dev/null -w "%{http_code}:%{ssl_verify_result}" https://dv-g3b-emudhra.we-have-a-problem.com/ 2>&1 || echo "error")
  HTTP=$(echo "$RESULT" | cut -d: -f1)
  VERIFY=$(echo "$RESULT" | cut -d: -f2)
  if [ "$HTTP" = "200" ] && [ "$VERIFY" = "0" ]; then
    log_fail "TLS dv-g3b (emSign direct)" "ACCEPTED — HTTP $HTTP, verify=$VERIFY"
  elif echo "$RESULT" | grep -q "error\|SSL\|certificate"; then
    log_pass "TLS dv-g3b (emSign direct)" "REJECTED — connection failed"
  else
    log_warn "TLS dv-g3b (emSign direct)" "inconclusive — $RESULT"
  fi

  # AAA cross-signed chain (should also be REJECTED)
  RESULT=$(curl -sS --max-time 15 -o /dev/null -w "%{http_code}:%{ssl_verify_result}" https://dv-g3b-aaa-emudhra.we-have-a-problem.com/ 2>&1 || echo "error")
  HTTP=$(echo "$RESULT" | cut -d: -f1)
  VERIFY=$(echo "$RESULT" | cut -d: -f2)
  if [ "$HTTP" = "200" ] && [ "$VERIFY" = "0" ]; then
    log_fail "TLS dv-g3b-aaa (cross-signed)" "ACCEPTED — HTTP $HTTP, verify=$VERIFY"
  elif echo "$RESULT" | grep -q "error\|SSL\|certificate"; then
    log_pass "TLS dv-g3b-aaa (cross-signed)" "REJECTED"
  else
    log_warn "TLS dv-g3b-aaa (cross-signed)" "inconclusive — $RESULT"
  fi
else
  log_warn "TLS tests" "curl not available"
fi

# --- 9. Nix cacert ---
[ "$JSON_MODE" = false ] && echo -e "\n${BOLD}Nix / Container${NC}"

if [ -d /nix/store ]; then
  NIX_CACERT=$(ls -d /nix/store/*nss-cacert* 2>/dev/null | head -1 || echo "")
  if [ -n "$NIX_CACERT" ]; then
    NIX_VER=$(basename "$NIX_CACERT" | grep -oE '[0-9]+\.[0-9]+' || echo "unknown")
    # NSS 3.131.1 has the fix
    if echo "$NIX_VER" | grep -qE '^3\.1[3-9][0-9]|^3\.131|^[4-9]'; then
      log_pass "Nix cacert" "nss-cacert-$NIX_VER (>= 3.131)"
    else
      log_fail "Nix cacert" "nss-cacert-$NIX_VER — needs >= 3.131.1"
    fi
  else
    log_info "Nix cacert" "no nss-cacert in /nix/store"
  fi
else
  log_info "Nix" "not a Nix environment"
fi

# tmpfs overlay
if mount 2>/dev/null | grep -q "on /etc/ssl/certs type tmpfs"; then
  log_warn "tmpfs overlay" "/etc/ssl/certs is a tmpfs mount — OS package updates may be overridden"
fi

# --- 10. Environment variables ---
[ "$JSON_MODE" = false ] && echo -e "\n${BOLD}Environment${NC}"

if [ -n "${REQUESTS_CA_BUNDLE:-}" ]; then
  log_info "REQUESTS_CA_BUNDLE" "$REQUESTS_CA_BUNDLE"
else
  log_info "REQUESTS_CA_BUNDLE" "not set"
fi
if [ -n "${CURL_CA_BUNDLE:-}" ]; then
  log_info "CURL_CA_BUNDLE" "$CURL_CA_BUNDLE"
fi
if [ -n "${NODE_OPTIONS:-}" ]; then
  if echo "$NODE_OPTIONS" | grep -q "use-openssl-ca"; then
    log_pass "NODE_OPTIONS" "contains --use-openssl-ca"
  else
    log_info "NODE_OPTIONS" "$NODE_OPTIONS (no --use-openssl-ca)"
  fi
fi

# --- summary ---
if [ "$JSON_MODE" = true ]; then
  echo "{"
  echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo "  \"hostname\": \"$(hostname 2>/dev/null || echo unknown)\","
  echo "  \"pass\": $PASS,"
  echo "  \"fail\": $FAIL,"
  echo "  \"warn\": $WARN,"
  echo "  \"results\": ["
  FIRST=true
  for r in "${JSON_RESULTS[@]}"; do
    [ "$FIRST" = true ] && FIRST=false || echo ","
    echo -n "    $r"
  done
  echo ""
  echo "  ]"
  echo "}"
else
  echo ""
  echo -e "${BOLD}Summary${NC}"
  echo -e "  ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}, ${YELLOW}$WARN warnings${NC}"
  echo ""
  if [ "$FAIL" -gt 0 ]; then
    echo -e "  ${RED}${BOLD}VULNERABLE${NC} — $FAIL check(s) indicate exposure to the eMudhra CA compromise."
    echo "  See https://github.com/user/emudhra-checker for remediation steps."
    exit 1
  else
    echo -e "  ${GREEN}${BOLD}No issues detected.${NC}"
    exit 0
  fi
fi
