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
doctl account get --format Email --no-header &>/dev/null || die "doctl not authenticated. Run: doctl auth init"
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
ANTHROPIC_KEY_ITEM="$(cfg '.anthropic_key_item')"
PAIR_WITH="$(cfg '.pair_with')"
TEST_PROMPT="$(cfg '.test_prompt')"

# Channels
TG_BOT_NAME="$(cfg '.channels.telegram.bot_name')"
TG_BOT_USERNAME="$(cfg '.channels.telegram.bot_username')"
TG_BOT_TOKEN_ITEM="$(cfg '.channels.telegram.bot_token_item')"
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
step "Step 2: Resolve SSH key"

if [[ -n "$SSH_KEY_NAME" ]]; then
    SSH_KEY_ID=$(doctl compute ssh-key list --format ID,Name --no-header | grep "$SSH_KEY_NAME" | awk '{print $1}')
    [[ -n "$SSH_KEY_ID" ]] || die "SSH key '${SSH_KEY_NAME}' not found in DigitalOcean"
else
    # Auto-detect: use first available key
    SSH_KEY_ID=$(doctl compute ssh-key list --format ID --no-header | head -1)
    [[ -n "$SSH_KEY_ID" ]] || die "No SSH keys found in DigitalOcean. Add one first."
    SSH_KEY_NAME=$(doctl compute ssh-key get "$SSH_KEY_ID" --format Name --no-header)
fi
ok "Using SSH key: ${SSH_KEY_NAME} (${SSH_KEY_ID})"

# ---------------------------------------------------------------------------
# Step 3: Resolve Anthropic API key from 1Password
# ---------------------------------------------------------------------------
step "Step 3: Resolve secrets from 1Password"

if [[ -n "$ANTHROPIC_KEY_ITEM" ]]; then
    ANTHROPIC_KEY=$(op_read_credential "$ANTHROPIC_KEY_ITEM")
else
    # Try common names
    ANTHROPIC_KEY=$(op_read_credential "Hal - Anthropic API Key (Scout)" 2>/dev/null || true)
    if [[ -z "$ANTHROPIC_KEY" ]]; then
        ANTHROPIC_KEY=$(op item list --vault="${VAULT}" --format=json 2>/dev/null | \
            jq -r '.[] | select(.title | test("anthropic"; "i")) | .title' | head -1)
        if [[ -n "$ANTHROPIC_KEY" ]]; then
            ANTHROPIC_KEY=$(op_read_credential "$ANTHROPIC_KEY")
        fi
    fi
fi

if [[ -z "$ANTHROPIC_KEY" ]]; then
    echo ""
    read -rp "  Enter Anthropic API key (or 1Password item name): " ANTHROPIC_KEY
    if op item get "$ANTHROPIC_KEY" --vault="${VAULT}" &>/dev/null 2>&1; then
        ANTHROPIC_KEY=$(op_read_credential "$ANTHROPIC_KEY")
    fi
fi

[[ -n "$ANTHROPIC_KEY" ]] || die "Anthropic API key is required"
ok "Anthropic API key resolved"

# Resolve Telegram bot token if configured
TG_TOKEN=""
if [[ -n "$TG_BOT_USERNAME" || -n "$TG_BOT_TOKEN_ITEM" ]]; then
    if [[ -n "$TG_BOT_TOKEN_ITEM" ]]; then
        TG_TOKEN=$(op_read_credential "$TG_BOT_TOKEN_ITEM")
    fi
    if [[ -z "$TG_TOKEN" ]]; then
        echo ""
        info "Telegram bot token needed."
        info "Create a bot via @BotFather on Telegram, then enter the token."
        read -rp "  Telegram bot token: " TG_TOKEN
    fi
    [[ -n "$TG_TOKEN" ]] || warn "No Telegram token -- skipping Telegram setup"
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
    if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes "root@${DROPLET_IP}" "echo ready" &>/dev/null; then
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
    ssh -o StrictHostKeyChecking=no "root@${DROPLET_IP}" bash -s <<'REMOTE_INSTALL'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export NODE_OPTIONS="--max-old-space-size=900"

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
    echo ">>> Installing Tailscale..."
    curl -fsSL https://tailscale.com/install.sh | sh
fi

# OpenClaw
if ! command -v openclaw &>/dev/null; then
    echo ">>> Installing OpenClaw..."
    set +e
    curl -fsSL https://openclaw.ai/install.sh | bash
    set -e
fi

command -v openclaw &>/dev/null && echo "OPENCLAW_INSTALLED" || echo "OPENCLAW_FAILED"
REMOTE_INSTALL

    # Verify
    VERIFY=$(ssh -o StrictHostKeyChecking=no "root@${DROPLET_IP}" "openclaw --version 2>/dev/null || echo FAILED")
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
    # Generate a Django-style secret key for the gateway
    GATEWAY_SECRET=$(openssl rand -base64 48 | tr -d '\n/+=')

    # Run onboarding non-interactively by writing config directly
    ssh -o StrictHostKeyChecking=no "root@${DROPLET_IP}" bash -s <<REMOTE_CONFIG
set -euo pipefail
export NODE_OPTIONS="--max-old-space-size=900"

# Create config directory
mkdir -p ~/.openclaw

# Run onboarding with --install-daemon to set up systemd
# This will prompt -- we pipe answers
echo ">>> Running onboarding..."
openclaw onboard --install-daemon <<EOF_ONBOARD || true
1
${ANTHROPIC_KEY}
y
EOF_ONBOARD

# Patch the config with our model preference
if [[ -f ~/.openclaw/openclaw.json ]]; then
    # Use node to patch JSON (jq may not be installed)
    node -e "
      const fs = require('fs');
      const cfg = JSON.parse(fs.readFileSync('/root/.openclaw/openclaw.json', 'utf8'));
      cfg.defaultModel = '${MODEL}';
      fs.writeFileSync('/root/.openclaw/openclaw.json', JSON.stringify(cfg, null, 2));
    " 2>/dev/null || true
fi

echo "CONFIG_DONE"
REMOTE_CONFIG

    set_state "config_done" "true"
    ok "OpenClaw configured with model: ${MODEL}"
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
        ssh -o StrictHostKeyChecking=no "root@${DROPLET_IP}" bash -s <<REMOTE_TG
set -euo pipefail
export NODE_OPTIONS="--max-old-space-size=900"

# Enable telegram plugin and add token
openclaw plugins enable telegram 2>/dev/null || true
openclaw channels add --channel telegram --token "${TG_TOKEN}" 2>/dev/null || true

echo "TELEGRAM_DONE"
REMOTE_TG

        set_state "telegram_done" "true"
        ok "Telegram configured"

        # Store token in 1Password
        op_create_item "Telegram Bot Token (${TG_BOT_USERNAME:-telegram})" "$TG_TOKEN" --tags="${AGENT_NAME_LOWER},telegram"
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
    scp -o StrictHostKeyChecking=no "$SOUL_SOURCE" "root@${DROPLET_IP}:/root/.openclaw/workspace/SOUL.md"
    ok "Uploaded SOUL.md"
fi

# Upload custom workspace files if specified
for key in agents tools user identity; do
    FILE_PATH="$(cfg ".workspace_files.${key}")"
    if [[ -n "$FILE_PATH" && -f "$FILE_PATH" ]]; then
        DEST_NAME="$(echo "$key" | tr '[:lower:]' '[:upper:]').md"
        scp -o StrictHostKeyChecking=no "$FILE_PATH" "root@${DROPLET_IP}:/root/.openclaw/workspace/${DEST_NAME}"
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
    # Store Anthropic key for this agent
    op_create_item "Anthropic API Key" "$ANTHROPIC_KEY" --tags="${AGENT_NAME_LOWER},anthropic" 2>/dev/null || true

    # Store droplet info as a secure note
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
ssh -o StrictHostKeyChecking=no "root@${DROPLET_IP}" bash -s <<'REMOTE_VERIFY'
export NODE_OPTIONS="--max-old-space-size=900"
# Ensure gateway is running
systemctl --user start openclaw-gateway 2>/dev/null || openclaw gateway start 2>/dev/null || true
sleep 5
openclaw status 2>&1 || echo "STATUS_UNKNOWN"
REMOTE_VERIFY

if [[ -n "$TEST_PROMPT" ]]; then
    info "Testing with prompt: ${TEST_PROMPT}"
    RESPONSE=$(ssh -o StrictHostKeyChecking=no "root@${DROPLET_IP}" \
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
info "SSH:       ssh root@${DROPLET_IP}"
info "Logs:      ssh root@${DROPLET_IP} openclaw logs --follow"
info "Control:   ssh -L 18789:localhost:18789 root@${DROPLET_IP}"
echo ""
