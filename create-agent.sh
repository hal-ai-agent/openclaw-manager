#!/usr/bin/env bash
#
# OpenClaw Manager -- Create Agent
#
# Provisions a new OpenClaw agent on DigitalOcean with secrets in 1Password.
#
# Usage:
#   ./create-agent.sh <agent-config.yaml>
#   ./create-agent.sh --resume <agent-name>    # Resume interrupted provisioning
#
# Timing expectations (s-1vcpu-2gb):
#   Step 4 (droplet create):  ~1-2 min
#   Step 5 (install):         ~8-12 min (apt upgrade + node + npm install)
#   Step 6 (configure):       ~30 sec
#   Step 7 (telegram):        ~15 sec
#   Total:                    ~12-15 min
#
set -euo pipefail

SCRIPT_VERSION="0.2.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${HOME}/.openclaw-manager"
LOG_DIR="/tmp/openclaw-manager-logs"
mkdir -p "$LOG_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

step()  { echo -e "\n${CYAN}=== $1${NC}"; }
ok()    { echo -e "  ${GREEN}OK:${NC} $1"; }
warn()  { echo -e "  ${YELLOW}WARN:${NC} $1"; }
fail()  { echo -e "  ${RED}FAIL:${NC} $1"; }
info()  { echo -e "  $1"; }
die()   { fail "$1"; exit 1; }

# ---------------------------------------------------------------------------
# Config parsing (uses yq for YAML)
# ---------------------------------------------------------------------------
ensure_yq() {
    if command -v yq &>/dev/null; then return; fi
    echo "  Installing yq..."
    local YQ_VERSION="v4.44.1"
    local ARCH; ARCH=$(uname -m)
    case "$ARCH" in x86_64) ARCH="amd64" ;; aarch64) ARCH="arm64" ;; *) die "Unsupported arch: $ARCH" ;; esac
    curl -fsSL "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_${ARCH}" -o /usr/local/bin/yq
    chmod +x /usr/local/bin/yq
    ok "yq installed"
}

cfg() { yq -r "$1 // \"\"" "$CONFIG_FILE"; }

# ---------------------------------------------------------------------------
# State management (resume support)
# ---------------------------------------------------------------------------
state_file() { echo "${STATE_DIR}/${AGENT_NAME}/state.json"; }
save_state() { mkdir -p "${STATE_DIR}/${AGENT_NAME}"; echo "$1" | jq '.' > "$(state_file)"; }
load_state() { local sf; sf="$(state_file)"; [[ -f "$sf" ]] && cat "$sf" || echo '{}'; }
get_state() { load_state | jq -r ".$1 // \"\""; }
set_state() { save_state "$(load_state | jq --arg k "$1" --arg v "$2" '. + {($k): $v}')"; }

# ---------------------------------------------------------------------------
# 1Password helpers
# ---------------------------------------------------------------------------
op_read_credential() {
    # --reveal is required to get the actual value (not masked "[use --reveal to reveal]")
    op item get "$1" --vault="${VAULT}" --fields credential --reveal 2>/dev/null || echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

echo -e "\n${CYAN}========================================${NC}"
echo -e "${CYAN}  OpenClaw Manager v${SCRIPT_VERSION}${NC}"
echo -e "${CYAN}========================================${NC}"

# Parse arguments
RESUME=false
if [[ "${1:-}" == "--resume" ]]; then
    RESUME=true
    AGENT_NAME="${2:?Usage: $0 --resume <agent-name>}"
    CONFIG_FILE="${STATE_DIR}/${AGENT_NAME}/config.yaml"
    [[ -f "$CONFIG_FILE" ]] || die "No saved config for agent '${AGENT_NAME}'"
else
    CONFIG_FILE="${1:?Usage: $0 <agent-config.yaml>}"
    [[ -f "$CONFIG_FILE" ]] || die "Config file not found: ${CONFIG_FILE}"
fi

# ---------------------------------------------------------------------------
# Step 0: Preflight
# ---------------------------------------------------------------------------
step "Step 0: Preflight"
command -v doctl &>/dev/null || die "doctl not found"
command -v op    &>/dev/null || die "op not found"
command -v jq    &>/dev/null || die "jq not found"
command -v ssh   &>/dev/null || die "ssh not found"
ensure_yq
doctl compute ssh-key list --no-header &>/dev/null || die "doctl not authenticated"
ok "doctl"
op whoami &>/dev/null || die "op not authenticated"
ok "op"

# ---------------------------------------------------------------------------
# Step 1: Parse config
# ---------------------------------------------------------------------------
step "Step 1: Config"

AGENT_NAME="$(cfg '.name')"
AGENT_NAME_LOWER="$(echo "$AGENT_NAME" | tr '[:upper:]' '[:lower:]')"
HOSTNAME="$(cfg '.hostname')"
REGION="$(cfg '.region')"
SIZE="$(cfg '.size')"
MODEL="$(cfg '.model')"
VAULT="$(cfg '.vault')"
ANTHROPIC_KEY_ITEM="$(cfg '.secrets.anthropic_api_key')"
TG_BOT_TOKEN_ITEM="$(cfg '.secrets.telegram_bot_token')"
PAIR_WITH="$(yq -r '.pair_with // [] | join(",")' "$CONFIG_FILE")"
TEST_PROMPT="$(cfg '.test_prompt')"
TG_BOT_USERNAME="$(cfg '.channels.telegram.bot_username')"
GMAIL_EMAIL="$(cfg '.channels.gmail.email')"
GMAIL_GCP_PROJECT="$(cfg '.channels.gmail.gcp_project')"

[[ -n "$AGENT_NAME" ]] || die "Agent name is required"
[[ -n "$HOSTNAME" ]]   || HOSTNAME="openclaw-${AGENT_NAME_LOWER}"
[[ -n "$REGION" ]]     || REGION="nyc3"
[[ -n "$SIZE" ]]       || SIZE="s-1vcpu-2gb"
[[ -n "$MODEL" ]]      || MODEL="anthropic/claude-sonnet-4-20250514"
[[ -n "$VAULT" ]]      || VAULT="AI-Agents"

info "Agent: ${AGENT_NAME} | Host: ${HOSTNAME} | Region: ${REGION} | Size: ${SIZE}"
mkdir -p "${STATE_DIR}/${AGENT_NAME}"
cp "$CONFIG_FILE" "${STATE_DIR}/${AGENT_NAME}/config.yaml"

# ---------------------------------------------------------------------------
# Step 2: SSH key
# ---------------------------------------------------------------------------
step "Step 2: SSH key"
SSH_KEY_FILE="$HOME/.ssh/${HOSTNAME}"
SSH_KEY_NAME="${HOSTNAME}"

[[ -f "$SSH_KEY_FILE" ]] || ssh-keygen -t ed25519 -f "$SSH_KEY_FILE" -N "" -C "$HOSTNAME" >/dev/null 2>&1
ok "Key: ${SSH_KEY_FILE}"

SSH_KEY_ID=$(doctl compute ssh-key list --format ID,Name --no-header 2>/dev/null | grep "$SSH_KEY_NAME" | awk '{print $1}' || true)
if [[ -z "$SSH_KEY_ID" ]]; then
    SSH_KEY_ID=$(doctl compute ssh-key create "$SSH_KEY_NAME" --public-key "$(cat "${SSH_KEY_FILE}.pub")" --format ID --no-header 2>&1)
    [[ -n "$SSH_KEY_ID" ]] || die "Failed to register SSH key"
fi
ok "DO key: ${SSH_KEY_ID}"

SSH_OPTS="-o StrictHostKeyChecking=no -o BatchMode=yes -i ${SSH_KEY_FILE}"

# ---------------------------------------------------------------------------
# Step 3: Secrets
# ---------------------------------------------------------------------------
step "Step 3: Secrets"
[[ -n "$ANTHROPIC_KEY_ITEM" ]] || die "secrets.anthropic_api_key required"
ANTHROPIC_KEY=$(op_read_credential "$ANTHROPIC_KEY_ITEM")
[[ -n "$ANTHROPIC_KEY" ]] || die "Could not read '$ANTHROPIC_KEY_ITEM'"
ok "anthropic_api_key"

TG_TOKEN=""
if [[ -n "$TG_BOT_TOKEN_ITEM" ]]; then
    TG_TOKEN=$(op_read_credential "$TG_BOT_TOKEN_ITEM")
    [[ -n "$TG_TOKEN" ]] || die "Could not read '$TG_BOT_TOKEN_ITEM'"
    ok "telegram_bot_token"
fi

# ---------------------------------------------------------------------------
# Step 4: Create droplet (~1-2 min)
# ---------------------------------------------------------------------------
step "Step 4: Droplet"
DROPLET_IP="$(get_state 'droplet_ip')"

if [[ -n "$DROPLET_IP" ]]; then
    ok "Exists: ${DROPLET_IP} (resuming)"
else
    info "Creating ${SIZE} in ${REGION}... (1-2 min)"
    CREATE_OUTPUT=$(doctl compute droplet create "$HOSTNAME" \
        --size "$SIZE" --image ubuntu-24-04-x64 --region "$REGION" \
        --ssh-keys "$SSH_KEY_ID" --format ID,Name,PublicIPv4 --no-header --wait 2>&1)
    DROPLET_ID=$(echo "$CREATE_OUTPUT" | awk '{print $1}')
    DROPLET_IP=$(echo "$CREATE_OUTPUT" | awk '{print $3}')
    [[ -n "$DROPLET_IP" ]] || die "Droplet creation failed: ${CREATE_OUTPUT}"
    set_state "droplet_id" "$DROPLET_ID"
    set_state "droplet_ip" "$DROPLET_IP"
    ok "Created: ${HOSTNAME} (${DROPLET_IP})"
fi

info "Waiting for SSH..."
for i in $(seq 1 30); do
    ssh -o ConnectTimeout=5 ${SSH_OPTS} "root@${DROPLET_IP}" "echo ready" &>/dev/null && break
    [[ $i -eq 30 ]] && die "SSH not ready after 150s"
    sleep 5
done
ok "SSH ready"

# ---------------------------------------------------------------------------
# Step 5: Install (~8-12 min)
# All output goes to log file; only milestones printed.
# ---------------------------------------------------------------------------
step "Step 5: Install (8-12 min, output → ${LOG_DIR}/${HOSTNAME}-install.log)"

INSTALL_DONE="$(get_state 'install_done')"

if [[ "$INSTALL_DONE" == "true" ]]; then
    ok "Already installed (resuming)"
else
    ssh ${SSH_OPTS} "root@${DROPLET_IP}" bash -s > "${LOG_DIR}/${HOSTNAME}-install.log" 2>&1 <<'REMOTE_INSTALL'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export NODE_OPTIONS="--max-old-space-size=900"

wait_for_apt() {
    while fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock >/dev/null 2>&1; do sleep 5; done
}

# Swap (before anything else)
TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}')
if [[ $TOTAL_MEM -lt 2048 ]] && [[ $(swapon --show | wc -l) -eq 0 ]]; then
    echo "MILESTONE: Adding swap"
    fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# Kill unattended-upgrades (main source of apt lock contention)
systemctl stop unattended-upgrades 2>/dev/null || true
systemctl disable unattended-upgrades 2>/dev/null || true

# Wait for cloud-init and any startup apt activity to fully finish
# This is the #1 cause of failures — cloud-init runs apt on fresh droplets
echo "MILESTONE: Waiting 60s for cloud-init apt to finish"
sleep 60
wait_for_apt

echo "MILESTONE: System update"
wait_for_apt
apt-get update -qq
wait_for_apt
apt-get upgrade -y -qq
wait_for_apt

echo "MILESTONE: Node.js 22"
if ! command -v node &>/dev/null || [[ "$(node --version)" != v22* ]]; then
    wait_for_apt
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    wait_for_apt
    apt-get install -y -qq nodejs
fi
echo "NODE_VERSION=$(node --version 2>/dev/null || echo NONE)"

echo "MILESTONE: Tailscale"
if ! command -v tailscale &>/dev/null; then
    wait_for_apt
    curl -fsSL https://tailscale.com/install.sh | sh
fi

# Generous wait for all background apt activity to settle
echo "MILESTONE: Waiting for apt to fully settle"
wait_for_apt
sleep 15
wait_for_apt

echo "MILESTONE: OpenClaw (npm)"
if ! command -v openclaw &>/dev/null; then
    npm install -g openclaw@latest 2>&1
fi

if command -v openclaw &>/dev/null; then
    echo "MILESTONE: SUCCESS $(openclaw --version 2>/dev/null)"
else
    echo "MILESTONE: FAILED"
    exit 1
fi
REMOTE_INSTALL

    # Check result
    if ! tail -1 "${LOG_DIR}/${HOSTNAME}-install.log" | grep -q "SUCCESS"; then
        fail "Install failed. Check ${LOG_DIR}/${HOSTNAME}-install.log"
        tail -20 "${LOG_DIR}/${HOSTNAME}-install.log"
        exit 1
    fi

    VERIFY=$(ssh ${SSH_OPTS} "root@${DROPLET_IP}" "openclaw --version 2>/dev/null || echo FAILED")
    set_state "install_done" "true"
    ok "OpenClaw ${VERIFY}"
fi

# ---------------------------------------------------------------------------
# Step 6: Configure (~30 sec)
# ---------------------------------------------------------------------------
step "Step 6: Configure"

CONFIG_DONE="$(get_state 'config_done')"

if [[ "$CONFIG_DONE" == "true" ]]; then
    ok "Already configured (resuming)"
else
    # Use openclaw onboard to generate correct config, then patch the real API key
    # The /dev/tty error from onboard is non-fatal — config still gets written
    REMOTE_OUTPUT=$(ssh ${SSH_OPTS} "root@${DROPLET_IP}" bash -s <<REMOTE_CONFIG
set -euo pipefail
export NODE_OPTIONS="--max-old-space-size=900"

# Stop any running gateway
openclaw gateway stop 2>&1 || true
rm -rf ~/.openclaw

# Run onboard (generates correct config schema + systemd service)
# The /dev/tty error at the end is expected and harmless in non-TTY SSH
openclaw onboard --non-interactive --accept-risk \
  --flow quickstart \
  --auth-choice apiKey \
  --anthropic-api-key '${ANTHROPIC_KEY}' \
  --gateway-port 18789 \
  --gateway-bind loopback \
  --install-daemon \
  --daemon-runtime node 2>&1 || true

# Set model
openclaw models set '${MODEL}' 2>&1 || true

# Verify auth-profiles.json has the key
if grep -q '"anthropic"' ~/.openclaw/agents/main/agent/auth-profiles.json 2>/dev/null; then
    echo "AUTH_FILE_OK"
else
    echo "AUTH_FAILED"
    exit 1
fi

# Verify API key works against Anthropic
if curl -sf -o /dev/null https://api.anthropic.com/v1/messages \
  -H "x-api-key: ${ANTHROPIC_KEY}" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-4-20250514","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}'; then
    echo "AUTH_VERIFIED"
else
    echo "AUTH_CURL_FAILED"
    exit 1
fi

echo "CONFIG_DONE"
REMOTE_CONFIG
)
    echo "$REMOTE_OUTPUT"

    if ! echo "$REMOTE_OUTPUT" | grep -q "CONFIG_DONE"; then
        die "Configuration failed"
    fi

    set_state "config_done" "true"
    ok "Configured (model: ${MODEL}, API key verified)"
fi

# ---------------------------------------------------------------------------
# Step 7: Telegram
# ---------------------------------------------------------------------------
if [[ -n "$TG_TOKEN" ]]; then
    step "Step 7: Telegram"

    TG_DONE="$(get_state 'telegram_done')"
    if [[ "$TG_DONE" == "true" ]]; then
        ok "Already configured (resuming)"
    else
        ALLOW_FROM_JSON="[]"
        if [[ -n "$PAIR_WITH" ]]; then
            ALLOW_FROM_JSON=$(echo "$PAIR_WITH" | tr ',' '\n' | jq -R . | jq -s .)
        fi

        ssh ${SSH_OPTS} "root@${DROPLET_IP}" bash -s <<REMOTE_TG
set -euo pipefail
export NODE_OPTIONS="--max-old-space-size=900"
openclaw config set channels.telegram.enabled true 2>&1
openclaw config set channels.telegram.botToken '${TG_TOKEN}' 2>&1
openclaw config set channels.telegram.dmPolicy allowlist 2>&1
openclaw config set channels.telegram.allowFrom '${ALLOW_FROM_JSON}' 2>&1
openclaw gateway restart 2>&1 || true
echo "TELEGRAM_DONE"
REMOTE_TG

        set_state "telegram_done" "true"
        ok "Telegram configured (users: ${PAIR_WITH})"
    fi
fi

# ---------------------------------------------------------------------------
# Step 8: Gmail (interactive — skip in automated mode)
# ---------------------------------------------------------------------------
if [[ -n "$GMAIL_EMAIL" ]]; then
    step "Step 8: Gmail"
    GMAIL_DONE="$(get_state 'gmail_done')"
    if [[ "$GMAIL_DONE" == "true" ]]; then
        ok "Already configured (resuming)"
    else
        warn "Gmail requires interactive OAuth — configure manually later"
        info "  ssh -i ${SSH_KEY_FILE} root@${DROPLET_IP}"
    fi
fi

# ---------------------------------------------------------------------------
# Step 9: Workspace files
# ---------------------------------------------------------------------------
step "Step 9: Workspace files"

SOUL_SOURCE="$(cfg '.workspace_files.soul')"
[[ -z "$SOUL_SOURCE" ]] && SOUL_SOURCE="${SCRIPT_DIR}/templates/SOUL.md"
if [[ -f "$SOUL_SOURCE" ]]; then
    scp -o StrictHostKeyChecking=no -i ${SSH_KEY_FILE} "$SOUL_SOURCE" "root@${DROPLET_IP}:/root/.openclaw/workspace/SOUL.md" 2>/dev/null
    ok "SOUL.md"
fi

for key in agents tools user identity; do
    FILE_PATH="$(cfg ".workspace_files.${key}")"
    if [[ -n "$FILE_PATH" && -f "$FILE_PATH" ]]; then
        DEST_NAME="$(echo "$key" | tr '[:lower:]' '[:upper:]').md"
        scp -o StrictHostKeyChecking=no -i ${SSH_KEY_FILE} "$FILE_PATH" "root@${DROPLET_IP}:/root/.openclaw/workspace/${DEST_NAME}" 2>/dev/null
        ok "${DEST_NAME}"
    fi
done

# ---------------------------------------------------------------------------
# Step 10: 1Password metadata
# ---------------------------------------------------------------------------
step "Step 10: 1Password"

SECRETS_DONE="$(get_state 'secrets_done')"
if [[ "$SECRETS_DONE" == "true" ]]; then
    ok "Already stored (resuming)"
else
    op item create \
        --category=secureNote \
        --title="${AGENT_NAME} - Droplet Info" \
        --vault="${VAULT}" \
        "notesPlain=Hostname: ${HOSTNAME}
IP: ${DROPLET_IP}
Region: ${REGION}
Size: ${SIZE}
Model: ${MODEL}
Created: $(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --tags="${AGENT_NAME_LOWER},infrastructure" \
        >/dev/null 2>&1 || true
    set_state "secrets_done" "true"
    ok "Droplet info stored"
fi

# ---------------------------------------------------------------------------
# Step 11: Verify
# ---------------------------------------------------------------------------
step "Step 11: Verify"

ssh ${SSH_OPTS} "root@${DROPLET_IP}" bash -s <<'REMOTE_VERIFY'
export NODE_OPTIONS="--max-old-space-size=900"
openclaw gateway restart 2>&1 || openclaw gateway start 2>&1 || true
sleep 10
openclaw status 2>&1 || echo "STATUS_UNKNOWN"
REMOTE_VERIFY

if [[ -n "$TEST_PROMPT" ]]; then
    info "Testing: ${TEST_PROMPT}"
    RESPONSE=$(ssh ${SSH_OPTS} "root@${DROPLET_IP}" \
        "export NODE_OPTIONS='--max-old-space-size=900'; timeout 30 openclaw agent -m '${TEST_PROMPT}' --agent main 2>&1" || true)
    if [[ -n "$RESPONSE" && "$RESPONSE" != *"rror"* ]]; then
        ok "Response: ${RESPONSE}"
    else
        warn "Test failed: ${RESPONSE}"
    fi
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Agent '${AGENT_NAME}' provisioned!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
info "Droplet:  ${HOSTNAME} (${DROPLET_IP})"
info "Model:    ${MODEL}"
[[ -n "$TG_TOKEN" ]] && info "Telegram: @${TG_BOT_USERNAME:-configured}"
info "SSH:      ssh -i ${SSH_KEY_FILE} root@${DROPLET_IP}"
echo ""
