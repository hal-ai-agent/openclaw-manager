#!/usr/bin/env bash
#
# OpenClaw Manager -- Install prerequisites
#
# Installs and verifies: doctl, op, jq, yq
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}OK:${NC} $1"; }
warn() { echo -e "  ${YELLOW}WARN:${NC} $1"; }
fail() { echo -e "  ${RED}FAIL:${NC} $1"; }

echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  OpenClaw Manager -- Install${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH_GO="amd64" ;;
    aarch64) ARCH_GO="arm64" ;;
    *)       fail "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# --- jq ---
if command -v jq &>/dev/null; then
    ok "jq already installed"
else
    echo "  Installing jq..."
    apt-get update -qq && apt-get install -y -qq jq
    ok "jq installed"
fi

# --- yq ---
if command -v yq &>/dev/null; then
    ok "yq already installed"
else
    echo "  Installing yq..."
    YQ_VERSION="v4.44.1"
    curl -fsSL "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_${ARCH_GO}" -o /usr/local/bin/yq
    chmod +x /usr/local/bin/yq
    ok "yq installed"
fi

# --- doctl ---
if command -v doctl &>/dev/null; then
    ok "doctl already installed ($(doctl version 2>&1 | head -1))"
else
    echo "  Installing doctl..."
    DOCTL_VERSION="1.104.0"
    curl -fsSL "https://github.com/digitalocean/doctl/releases/download/v${DOCTL_VERSION}/doctl-${DOCTL_VERSION}-linux-${ARCH_GO}.tar.gz" | tar xz -C /usr/local/bin
    ok "doctl installed"
fi

# Check doctl auth
if doctl compute ssh-key list --no-header &>/dev/null 2>&1; then
    DOCTL_EMAIL="authenticated"
    ok "doctl authenticated as ${DOCTL_EMAIL}"
else
    warn "doctl not authenticated. Run: doctl auth init"
fi

# --- op ---
if command -v op &>/dev/null; then
    ok "op already installed ($(op --version 2>/dev/null))"
else
    echo "  Installing 1Password CLI..."
    curl -sS https://downloads.1password.com/linux/keys/1password.asc | gpg --dearmor --output /usr/share/keyrings/1password-archive-keyring.gpg
    echo "deb [arch=${ARCH_GO} signed-by=/usr/share/keyrings/1password-archive-keyring.gpg] https://downloads.1password.com/linux/debian/${ARCH_GO} stable main" > /etc/apt/sources.list.d/1password.list
    mkdir -p /etc/debsig/policies/AC2D62742012EA22/
    curl -sS https://downloads.1password.com/linux/debian/debsig/1password.pol > /etc/debsig/policies/AC2D62742012EA22/1password.pol
    mkdir -p /usr/share/debsig/keyrings/AC2D62742012EA22
    curl -sS https://downloads.1password.com/linux/keys/1password.asc | gpg --dearmor --output /usr/share/debsig/keyrings/AC2D62742012EA22/debsig.gpg
    apt-get update -qq && apt-get install -y -qq 1password-cli
    ok "op installed"
fi

# Check op auth
if op whoami &>/dev/null 2>&1; then
    OP_EMAIL=$(op whoami --format json 2>/dev/null | jq -r '.email // "unknown"')
    ok "op authenticated as ${OP_EMAIL}"
else
    warn "op not authenticated. Run: op account add && eval \$(op signin)"
fi

# --- Download rig files ---
echo ""
echo -e "${CYAN}  Downloading rig files...${NC}"
RIG_DIR="${HOME}/.openclaw-manager/rig"
mkdir -p "${RIG_DIR}/templates"

BASE_URL="https://raw.githubusercontent.com/hal-ai-agent/openclaw-manager/main"
curl -fsSL "${BASE_URL}/preflight.sh" -o "${RIG_DIR}/preflight.sh"
chmod +x "${RIG_DIR}/preflight.sh"
curl -fsSL "${BASE_URL}/create-agent.sh" -o "${RIG_DIR}/create-agent.sh"
chmod +x "${RIG_DIR}/create-agent.sh"
curl -fsSL "${BASE_URL}/templates/agent-config.yaml" -o "${RIG_DIR}/templates/agent-config.yaml"
curl -fsSL "${BASE_URL}/templates/SOUL.md" -o "${RIG_DIR}/templates/SOUL.md"

ok "Rig files downloaded to ${RIG_DIR}"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Manager installed!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "  Next steps:"
echo "    1. Copy and edit the agent config:"
echo "       cp ${RIG_DIR}/templates/agent-config.yaml my-agent.yaml"
echo "    2. Fill in the config (name, channels, etc.)"
echo "    3. Run:"
echo "       ${RIG_DIR}/create-agent.sh my-agent.yaml"
echo ""
