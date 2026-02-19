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
# Prerequisites:
#   - doctl (authenticated)
#   - op (authenticated)
#   - jq
#   - yq (installed automatically if missing)
#   - SSH key registered with DigitalOcean
#
set -euo pipefail

SCRIPT_VERSION="0.1.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${HOME}/.openclaw-manager"

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

die() { fail "$1"; exit 1; }

# ---------------------------------------------------------------------------
# Config parsing (uses yq for YAML)
# ---------------------------------------------------------------------------
ensure_yq() {
    if command -v yq &>/dev/null; then return; fi
    echo "  Installing yq..."
    local YQ_VERSION="v4.44.1"
    local ARCH
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *)       die "Unsupported architecture: $ARCH" ;;
    esac
    curl -fsSL "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_${ARCH}" -o /usr/local/bin/yq
    chmod +x /usr/local/bin/yq
    ok "yq installed"
}

cfg() {
    # Read a value from the config YAML. Returns empty string if not found.
    yq -r "$1 // \"\"" "$CONFIG_FILE"
}

# ---------------------------------------------------------------------------
# State management (resume support)
# ---------------------------------------------------------------------------
state_file() { echo "${STATE_DIR}/${AGENT_NAME}/state.json"; }

save_state() {
    mkdir -p "${STATE_DIR}/${AGENT_NAME}"
    echo "$1" | jq '.' > "$(state_file)"
}

load_state() {
    local sf
    sf="$(state_file)"
    if [[ -f "$sf" ]]; then
        cat "$sf"
    else
        echo '{}'
    fi
}

get_state() { load_state | jq -r ".$1 // \"\""; }

set_state() {
    local current
    current="$(load_state)"
    save_state "$(echo "$current" | jq --arg k "$1" --arg v "$2" '. + {($k): $v}')"
}

# ---------------------------------------------------------------------------
# 1Password helpers
# ---------------------------------------------------------------------------
op_create_item() {
    # Usage: op_create_item "Title" "credential_value" [extra_args...]
    local title="$1" credential="$2"
    shift 2
    op item create \
        --category=apiCredential \
        --title="${AGENT_NAME} - ${title}" \
        --vault="${VAULT}" \
        "credential=${credential}" \
        "$@" \
        --tags="${AGENT_NAME_LOWER}" \
        >/dev/null 2>&1
    ok "1Password: ${AGENT_NAME} - ${title}"
}

op_create_login() {
    local title="$1" username="$2" password="$3"
    shift 3
    op item create \
        --category=login \
        --title="${AGENT_NAME} - ${title}" \
        --vault="${VAULT}" \
        "username=${username}" \
        "password=${password}" \
        "$@" \
        --tags="${AGENT_NAME_LOWER}" \
        >/dev/null 2>&1
    ok "1Password: ${AGENT_NAME} - ${title}"
}

op_read_credential() {
    # Read a credential from 1Password by item title
    local title="$1"
    op item get "$title" --vault="${VAULT}" --fields credential 2>/dev/null || echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  OpenClaw Manager v${SCRIPT_VERSION}${NC}"
echo -e "${CYAN}  Create Agent${NC}"
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
# Step 0: Preflight checks
# ---------------------------------------------------------------------------
step "Step 0: Preflight checks"

command -v doctl &>/dev/null || die "doctl not found. Install: https://docs.digitalocean.com/reference/doctl/how-to/install/"
command -v op    &>/dev/null || die "op not found. Install: https://developer.1password.com/docs/cli/get-started/"
command -v jq    &>/dev/null || die "jq not found. Install: apt-get install jq"
command -v ssh   &>/dev/null || die "ssh not found"
ensure_yq

# Verify auth
doctl compute ssh-key list --no-header &>/dev/null || die "doctl not authenticated or missing permissions. Run: doctl auth init"
ok "doctl authenticated"

op whoami &>/dev/null || die "op not authenticated. Run: op signin"
ok "op authenticated"

# ---------------------------------------------------------------------------
# Step 1: Parse config
# ---------------------------------------------------------------------------
step "Step 1: Parse agent config"

AGENT_NAME="$(cfg '.name')"
AGENT_NAME_LOWER="$(echo "$AGENT_NAME" | tr '[:upper:]' '[:lower:]')"
HOSTNAME="$(cfg '.hostname')"
REGION="$(cfg '.region')"
SIZE="$(cfg '.size')"
SSH_KEY_NAME="$(cfg '.ssh_key_name')"
MODEL="$(cfg '.model')"
VAULT="$(cfg '.vault')"
# Secrets (1Password item names)
ANTHROPIC_KEY_ITEM="$(cfg '.secrets.anthropic_api_key')"
TG_BOT_TOKEN_ITEM="$(cfg '.secrets.telegram_bot_token')"

# pair_with can be a string or array; flatten to comma-separated
PAIR_WITH="$(yq -r '.pair_with // [] | join(",")' "$CONFIG_FILE")"
TEST_PROMPT="$(cfg '.test_prompt')"

# Channels
TG_BOT_NAME="$(cfg '.channels.telegram.bot_name')"
TG_BOT_USERNAME="$(cfg '.channels.telegram.bot_username')"
GMAIL_EMAIL="$(cfg '.channels.gmail.email')"
GMAIL_GCP_PROJECT="$(cfg '.channels.gmail.gcp_project')"

[[ -n "$AGENT_NAME" ]] || die "Agent name is required"
[[ -n "$HOSTNAME" ]]   || HOSTNAME="openclaw-${AGENT_NAME_LOWER}"
[[ -n "$REGION" ]]     || REGION="nyc3"
[[ -n "$SIZE" ]]       || SIZE="s-1vcpu-2gb"
[[ -n "$MODEL" ]]      || MODEL="anthropic/claude-sonnet-4-20250514"
[[ -n "$VAULT" ]]      || VAULT="AI-Agents"

info "Agent:    ${AGENT_NAME}"
info "Hostname: ${HOSTNAME}"
info "Region:   ${REGION}"
info "Size:     ${SIZE}"
info "Model:    ${MODEL}"
info "Vault:    ${VAULT}"

# Save config for resume
mkdir -p "${STATE_DIR}/${AGENT_NAME}"
cp "$CONFIG_FILE" "${STATE_DIR}/${AGENT_NAME}/config.yaml"

# ---------------------------------------------------------------------------
# Step 2: Resolve SSH key
# ---------------------------------------------------------------------------
step "Step 2: Generate SSH key for ${AGENT_NAME}"

SSH_KEY_FILE="$HOME/.ssh/${HOSTNAME}"
SSH_KEY_NAME="${HOSTNAME}"

if [[ -f "$SSH_KEY_FILE" ]]; then
    ok "SSH key already exists: ${SSH_KEY_FILE}"
else
    ssh-keygen -t ed25519 -f "$SSH_KEY_FILE" -N "" -C "$HOSTNAME" >/dev/null 2>&1
    ok "Generated SSH key: ${SSH_KEY_FILE}"
fi

# Check if key already registered in DO
SSH_KEY_ID=$(doctl compute ssh-key list --format ID,Name --no-header 2>/dev/null | grep "$SSH_KEY_NAME" | awk '{print $1}' || true)
if [[ -n "$SSH_KEY_ID" ]]; then
    ok "SSH key already in DigitalOcean: ${SSH_KEY_NAME} (${SSH_KEY_ID})"
else
    SSH_KEY_ID=$(doctl compute ssh-key create "$SSH_KEY_NAME" \
        --public-key "$(cat "${SSH_KEY_FILE}.pub")" \
        --format ID --no-header 2>&1)
    [[ -n "$SSH_KEY_ID" ]] || die "Failed to register SSH key with DigitalOcean"
    ok "Registered SSH key in DigitalOcean: ${SSH_KEY_NAME} (${SSH_KEY_ID})"
fi

# SSH options used for all remote commands
SSH_OPTS="-o StrictHostKeyChecking=no -o BatchMode=yes -i ${SSH_KEY_FILE}"

# ---------------------------------------------------------------------------
# Step 3: Resolve Anthropic API key from 1Password
# ---------------------------------------------------------------------------
step "Step 3: Resolve secrets from 1Password"

[[ -n "$ANTHROPIC_KEY_ITEM" ]] || die "secrets.anthropic_api_key is required in config"
ANTHROPIC_KEY=$(op_read_credential "$ANTHROPIC_KEY_ITEM")
[[ -n "$ANTHROPIC_KEY" ]] || die "Could not read '$ANTHROPIC_KEY_ITEM' from vault '$VAULT'"
ok "anthropic_api_key → '$ANTHROPIC_KEY_ITEM'"

TG_TOKEN=""
if [[ -n "$TG_BOT_TOKEN_ITEM" ]]; then
    TG_TOKEN=$(op_read_credential "$TG_BOT_TOKEN_ITEM")
    [[ -n "$TG_TOKEN" ]] || die "Could not read '$TG_BOT_TOKEN_ITEM' from vault '$VAULT'"
    ok "telegram_bot_token → '$TG_BOT_TOKEN_ITEM'"
fi

# ---------------------------------------------------------------------------
# Step 4: Create droplet
# ---------------------------------------------------------------------------
step "Step 4: Create DigitalOcean droplet"

DROPLET_IP="$(get_state 'droplet_ip')"

if [[ -n "$DROPLET_IP" ]]; then
    ok "Droplet already created: ${DROPLET_IP} (resuming)"
else
    info "Creating ${SIZE} droplet in ${REGION}..."

    CREATE_OUTPUT=$(doctl compute droplet create "$HOSTNAME" \
        --size "$SIZE" \
        --image ubuntu-24-04-x64 \
        --region "$REGION" \
        --ssh-keys "$SSH_KEY_ID" \
        --format ID,Name,PublicIPv4 \
        --no-header \
        --wait 2>&1)

    DROPLET_ID=$(echo "$CREATE_OUTPUT" | awk '{print $1}')
    DROPLET_IP=$(echo "$CREATE_OUTPUT" | awk '{print $3}')

    [[ -n "$DROPLET_IP" ]] || die "Failed to create droplet: ${CREATE_OUTPUT}"

    set_state "droplet_id" "$DROPLET_ID"
    set_state "droplet_ip" "$DROPLET_IP"

    ok "Droplet created: ${HOSTNAME} (${DROPLET_IP})"
fi

# Wait for SSH
info "Waiting for SSH..."
for i in $(seq 1 30); do
    if ssh -o ConnectTimeout=5 ${SSH_OPTS} "root@${DROPLET_IP}" "echo ready" &>/dev/null; then
        ok "SSH ready"
        break
    fi
    [[ $i -eq 30 ]] && die "SSH not ready after 150s"
    sleep 5
done

# ---------------------------------------------------------------------------
# Step 5: Install OpenClaw on droplet
# ---------------------------------------------------------------------------
step "Step 5: Install OpenClaw"

INSTALL_DONE="$(get_state 'install_done')"

if [[ "$INSTALL_DONE" == "true" ]]; then
    ok "OpenClaw already installed (resuming)"
else
    # Upload and run the droplet setup inline (minimal -- no interactive prompts)
    ssh ${SSH_OPTS} "root@${DROPLET_IP}" bash -s <<'REMOTE_INSTALL'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export NODE_OPTIONS="--max-old-space-size=900"

# Wait for any background apt processes to finish
wait_for_apt() {
    local tries=0
    while fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock >/dev/null 2>&1; do
        if [[ $tries -eq 0 ]]; then echo ">>> Waiting for apt lock..."; fi
        sleep 5
        tries=$((tries + 1))
        [[ $tries -lt 60 ]] || { echo "ERROR: apt lock timeout"; exit 1; }
    done
}

wait_for_apt
echo ">>> Updating system..."
apt-get update -qq && apt-get upgrade -y -qq

# Swap for small droplets
TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}')
if [[ $TOTAL_MEM -lt 2048 ]] && [[ $(swapon --show | wc -l) -eq 0 ]]; then
    echo ">>> Adding 2GB swap..."
    fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# Node.js 22
if ! command -v node &>/dev/null || [[ "$(node --version)" != v22* ]]; then
    echo ">>> Installing Node.js 22..."
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    apt-get install -y -qq nodejs
fi

# Tailscale
if ! command -v tailscale &>/dev/null; then
    wait_for_apt
    echo ">>> Installing Tailscale..."
    curl -fsSL https://tailscale.com/install.sh | sh
fi

# OpenClaw
if ! command -v openclaw &>/dev/null; then
    wait_for_apt
    echo ">>> Installing OpenClaw..."
    set +e
    curl -fsSL https://openclaw.ai/install.sh | bash
    set -e
fi

command -v openclaw &>/dev/null && echo "OPENCLAW_INSTALLED" || echo "OPENCLAW_FAILED"
REMOTE_INSTALL

    # Verify
    VERIFY=$(ssh ${SSH_OPTS} "root@${DROPLET_IP}" "openclaw --version 2>/dev/null || echo FAILED")
    if [[ "$VERIFY" == "FAILED" ]]; then
        die "OpenClaw installation failed"
    fi

    set_state "install_done" "true"
    ok "OpenClaw installed: ${VERIFY}"
fi

# ---------------------------------------------------------------------------
# Step 6: Configure OpenClaw
# ---------------------------------------------------------------------------
step "Step 6: Configure OpenClaw"

CONFIG_DONE="$(get_state 'config_done')"

if [[ "$CONFIG_DONE" == "true" ]]; then
    ok "OpenClaw already configured (resuming)"
else
    # Use openclaw onboard --non-interactive for proper setup
    # Must run on a clean ~/.openclaw (no stale state from prior attempts)
    REMOTE_OUTPUT=$(ssh ${SSH_OPTS} "root@${DROPLET_IP}" bash -s <<REMOTE_CONFIG
set -euo pipefail
export NODE_OPTIONS="--max-old-space-size=900"

# Clean slate — onboard works best without pre-existing state
openclaw gateway stop 2>&1 || true
rm -rf ~/.openclaw

openclaw onboard --non-interactive --accept-risk \
  --mode local \
  --auth-choice apiKey \
  --anthropic-api-key '${ANTHROPIC_KEY}' \
  --gateway-port 18789 \
  --gateway-bind loopback \
  --install-daemon \
  --daemon-runtime node \
  --skip-skills 2>&1

# Set default model
openclaw models set '${MODEL}' 2>&1 || true

# Verify auth-profiles.json was written correctly
if grep -q '"anthropic"' ~/.openclaw/agents/main/agent/auth-profiles.json 2>/dev/null; then
    echo "AUTH_FILE_OK"
else
    echo "AUTH_FAILED: auth-profiles.json not written correctly" >&2
    exit 1
fi

# Verify the API key is valid by hitting Anthropic directly
if curl -sf -o /dev/null https://api.anthropic.com/v1/messages \
  -H "x-api-key: ${ANTHROPIC_KEY}" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-4-20250514","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}'; then
    echo "AUTH_VERIFIED"
else
    echo "AUTH_FAILED: Anthropic API key is invalid" >&2
    exit 1
fi

echo "CONFIG_DONE"
REMOTE_CONFIG
)
    echo "$REMOTE_OUTPUT"

    if echo "$REMOTE_OUTPUT" | grep -q "AUTH_FAILED"; then
        die "Auth verification failed — check remote output above"
    fi
    if ! echo "$REMOTE_OUTPUT" | grep -q "AUTH_VERIFIED"; then
        die "Verification did not complete — check remote output above"
    fi

    set_state "config_done" "true"
    ok "OpenClaw configured with model: ${MODEL} (API key verified)"
fi

# ---------------------------------------------------------------------------
# Step 7: Set up Telegram channel
# ---------------------------------------------------------------------------
if [[ -n "$TG_TOKEN" ]]; then
    step "Step 7: Configure Telegram"

    TG_DONE="$(get_state 'telegram_done')"
    if [[ "$TG_DONE" == "true" ]]; then
        ok "Telegram already configured (resuming)"
    else
        # Build allowFrom JSON array from PAIR_WITH
        ALLOW_FROM_JSON="[]"
        if [[ -n "$PAIR_WITH" ]]; then
            ALLOW_FROM_JSON=$(echo "$PAIR_WITH" | tr ',' '\n' | jq -R . | jq -s .)
        fi

        ssh ${SSH_OPTS} "root@${DROPLET_IP}" bash -s <<REMOTE_TG
set -euo pipefail
export NODE_OPTIONS="--max-old-space-size=900"

# Configure Telegram via config set (no interactive prompts)
openclaw config set channels.telegram.enabled true 2>&1
openclaw config set channels.telegram.botToken '${TG_TOKEN}' 2>&1
openclaw config set channels.telegram.dmPolicy allowlist 2>&1
openclaw config set channels.telegram.allowFrom '${ALLOW_FROM_JSON}' 2>&1

# Restart gateway to pick up Telegram config
openclaw gateway restart 2>&1 || true

echo "TELEGRAM_DONE"
REMOTE_TG

        set_state "telegram_done" "true"
        ok "Telegram configured (gateway restarted)"
        if [[ -n "$PAIR_WITH" ]]; then
            ok "Pre-approved users: ${PAIR_WITH}"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Step 8: Set up Gmail (guided -- requires OAuth)
# ---------------------------------------------------------------------------
if [[ -n "$GMAIL_EMAIL" ]]; then
    step "Step 8: Gmail setup"

    GMAIL_DONE="$(get_state 'gmail_done')"
    if [[ "$GMAIL_DONE" == "true" ]]; then
        ok "Gmail already configured (resuming)"
    else
        echo ""
        info "Gmail requires interactive OAuth. You'll need to:"
        info "  1. Ensure Tailscale is connected on the droplet"
        info "  2. Set up gog OAuth credentials"
        info "  3. Authorize the Gmail account"
        echo ""
        info "SSH into the droplet to complete Gmail setup:"
        info "  ssh root@${DROPLET_IP}"
        info "  openclaw webhooks gmail setup --account ${GMAIL_EMAIL} --project ${GMAIL_GCP_PROJECT}"
        echo ""
        read -rp "  Press Enter after completing Gmail setup (or 'skip' to skip): " gmail_response
        if [[ "$gmail_response" != "skip" ]]; then
            set_state "gmail_done" "true"
            ok "Gmail setup marked complete"
        else
            warn "Gmail skipped -- configure manually later"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Step 9: Upload workspace files
# ---------------------------------------------------------------------------
step "Step 9: Upload workspace files"

# Upload SOUL.md template
SOUL_SOURCE="$(cfg '.workspace_files.soul')"
if [[ -z "$SOUL_SOURCE" ]]; then
    SOUL_SOURCE="${SCRIPT_DIR}/templates/SOUL.md"
fi

if [[ -f "$SOUL_SOURCE" ]]; then
    scp -o StrictHostKeyChecking=no -i ${SSH_KEY_FILE} "$SOUL_SOURCE" "root@${DROPLET_IP}:/root/.openclaw/workspace/SOUL.md"
    ok "Uploaded SOUL.md"
fi

# Upload custom workspace files if specified
for key in agents tools user identity; do
    FILE_PATH="$(cfg ".workspace_files.${key}")"
    if [[ -n "$FILE_PATH" && -f "$FILE_PATH" ]]; then
        DEST_NAME="$(echo "$key" | tr '[:lower:]' '[:upper:]').md"
        scp -o StrictHostKeyChecking=no -i ${SSH_KEY_FILE} "$FILE_PATH" "root@${DROPLET_IP}:/root/.openclaw/workspace/${DEST_NAME}"
        ok "Uploaded ${DEST_NAME}"
    fi
done

# ---------------------------------------------------------------------------
# Step 10: Store secrets in 1Password
# ---------------------------------------------------------------------------
step "Step 10: Store secrets in 1Password"

SECRETS_DONE="$(get_state 'secrets_done')"

if [[ "$SECRETS_DONE" == "true" ]]; then
    ok "Secrets already stored (resuming)"
else
    # Secrets (Anthropic key, Telegram token) are already in 1Password.
    # Just store droplet info as a secure note.
    op item create \
        --category=secureNote \
        --title="${AGENT_NAME} - Droplet Info" \
        --vault="${VAULT}" \
        "notesPlain=Hostname: ${HOSTNAME}
IP: ${DROPLET_IP}
Region: ${REGION}
Size: ${SIZE}
Droplet ID: $(get_state 'droplet_id')
Model: ${MODEL}
Created: $(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --tags="${AGENT_NAME_LOWER},infrastructure" \
        >/dev/null 2>&1 || true
    ok "Stored droplet info"

    set_state "secrets_done" "true"
fi

# ---------------------------------------------------------------------------
# Step 11: Verify agent is running
# ---------------------------------------------------------------------------
step "Step 11: Verify agent"

info "Starting gateway..."
ssh ${SSH_OPTS} "root@${DROPLET_IP}" bash -s <<'REMOTE_VERIFY'
export NODE_OPTIONS="--max-old-space-size=900"
# Restart gateway to pick up all config changes
openclaw gateway restart 2>&1 || openclaw gateway start 2>&1 || true
sleep 8
openclaw status 2>&1 || echo "STATUS_UNKNOWN"
REMOTE_VERIFY

if [[ -n "$TEST_PROMPT" ]]; then
    info "Testing with prompt: ${TEST_PROMPT}"
    RESPONSE=$(ssh ${SSH_OPTS} "root@${DROPLET_IP}" \
        "export NODE_OPTIONS='--max-old-space-size=900'; timeout 30 openclaw agent -m '${TEST_PROMPT}' --agent main 2>&1" || true)
    if [[ -n "$RESPONSE" && "$RESPONSE" != *"error"* && "$RESPONSE" != *"Error"* ]]; then
        ok "Agent responded: ${RESPONSE}"
    else
        warn "Agent test failed or timed out: ${RESPONSE}"
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
info "Droplet:   ${HOSTNAME} (${DROPLET_IP})"
info "Model:     ${MODEL}"
info "Region:    ${REGION}"
info "1Password: ${VAULT} (prefix: ${AGENT_NAME} -)"
[[ -n "$TG_TOKEN" ]] && info "Telegram:  @${TG_BOT_USERNAME:-configured}"
[[ -n "$GMAIL_EMAIL" ]] && info "Gmail:     ${GMAIL_EMAIL}"
echo ""
info "SSH:       ssh -i ${SSH_KEY_FILE} root@${DROPLET_IP}"
info "Logs:      ssh -i ${SSH_KEY_FILE} root@${DROPLET_IP} openclaw logs --follow"
info "Control:   ssh -i ${SSH_KEY_FILE} -L 18789:localhost:18789 root@${DROPLET_IP}"
echo ""
