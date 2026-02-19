#!/usr/bin/env bash
#
# OpenClaw Manager — Preflight Check
#
# Verifies you can actually run create-agent.sh successfully.
# Only tests things that would cause the provisioning to fail.
#
# Usage:
#   ./preflight.sh <agent-config.yaml>
#
set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

pass() { echo -e "  ${GREEN}OK${NC}    $1"; ((PASS++)); }
fail() { echo -e "  ${RED}FAIL${NC}  $1"; ((FAIL++)); }
warn() { echo -e "  ${YELLOW}WARN${NC}  $1"; ((WARN++)); }
info() { echo -e "        $1"; }

CONFIG_FILE="${1:-}"
if [[ -z "$CONFIG_FILE" ]]; then
    echo "Usage: ./preflight.sh <agent-config.yaml>"
    exit 1
fi
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Config file not found: $CONFIG_FILE"
    exit 1
fi

# ---------------------------------------------------------------
# 1. Required tools present and authenticated
# ---------------------------------------------------------------
echo ""
echo -e "${CYAN}${BOLD}=== Tools & Auth ===${NC}"
echo ""

# doctl
if ! command -v doctl &>/dev/null; then
    fail "doctl not installed"
    info "Install: https://docs.digitalocean.com/reference/doctl/how-to/install/"
elif ! doctl compute droplet list --no-header &>/dev/null 2>&1; then
    fail "doctl not authenticated or missing Droplet scope"
    info "Fix: doctl auth init --access-token <token>"
else
    pass "doctl authenticated (droplet access)"
fi

# op
if ! command -v op &>/dev/null; then
    fail "op (1Password CLI) not installed"
    info "Install: https://developer.1password.com/docs/cli/get-started/"
elif ! op whoami &>/dev/null 2>&1; then
    fail "op not authenticated"
    info "Set OP_SERVICE_ACCOUNT_TOKEN env var"
else
    pass "op authenticated"
fi

# yq (needed to parse the config)
if ! command -v yq &>/dev/null; then
    fail "yq not installed (needed to parse config)"
    info "Install: https://github.com/mikefarah/yq/releases"
else
    pass "yq installed"
fi

# ---------------------------------------------------------------
# 2. DigitalOcean: SSH key exists
# ---------------------------------------------------------------
echo ""
echo -e "${CYAN}${BOLD}=== DigitalOcean ===${NC}"
echo ""

if command -v doctl &>/dev/null && doctl compute ssh-key list --no-header &>/dev/null 2>&1; then
    SSH_KEY_COUNT=$(doctl compute ssh-key list --format ID --no-header 2>/dev/null | wc -l)
    if [[ $SSH_KEY_COUNT -gt 0 ]]; then
        pass "SSH key registered ($SSH_KEY_COUNT available)"
    else
        fail "No SSH keys in DigitalOcean"
        info "Add one: doctl compute ssh-key create my-key --public-key-file ~/.ssh/id_ed25519.pub"
    fi
else
    fail "Cannot check SSH keys (doctl issue)"
fi

# ---------------------------------------------------------------
# 3. 1Password: vault and Anthropic key
# ---------------------------------------------------------------
echo ""
echo -e "${CYAN}${BOLD}=== 1Password ===${NC}"
echo ""

if command -v yq &>/dev/null; then
    VAULT=$(yq -r '.vault // "AI-Agents"' "$CONFIG_FILE")
else
    VAULT="AI-Agents"
fi

if command -v op &>/dev/null && op whoami &>/dev/null 2>&1; then
    if op vault get "$VAULT" &>/dev/null 2>&1; then
        pass "Vault '$VAULT' accessible"
    else
        fail "Vault '$VAULT' not found"
        info "Available: $(op vault list --format json 2>/dev/null | jq -r '[.[].name] | join(", ")')"
    fi

    # Check all secrets declared in the config
    if command -v yq &>/dev/null; then
        SECRET_KEYS=$(yq -r '.secrets // {} | keys | .[]' "$CONFIG_FILE" 2>/dev/null)
        if [[ -z "$SECRET_KEYS" ]]; then
            fail "No secrets declared in config (need at least anthropic_api_key)"
        else
            while IFS= read -r key; do
                ITEM_TITLE=$(yq -r ".secrets.${key}" "$CONFIG_FILE")
                if [[ -z "$ITEM_TITLE" || "$ITEM_TITLE" == "null" ]]; then
                    fail "Secret '$key' has no 1Password item name"
                elif op item get "$ITEM_TITLE" --vault="$VAULT" &>/dev/null 2>&1; then
                    pass "Secret '$key' → '$ITEM_TITLE'"
                else
                    fail "Secret '$key' → '$ITEM_TITLE' not found in vault '$VAULT'"
                fi
            done <<< "$SECRET_KEYS"
        fi
    fi
else
    fail "Cannot check 1Password (auth issue)"
fi

# ---------------------------------------------------------------
# 4. Agent config: required fields + channel readiness
# ---------------------------------------------------------------
echo ""
echo -e "${CYAN}${BOLD}=== Agent Config ===${NC}"
echo ""

if ! command -v yq &>/dev/null; then
    fail "Cannot validate config (yq missing)"
else
    # Name is required
    NAME=$(yq -r '.name // ""' "$CONFIG_FILE")
    if [[ -n "$NAME" ]]; then
        pass "Agent name: $NAME"
    else
        fail "Missing required field: name"
    fi

    # Telegram: check bot_username is set if telegram channel configured
    TG_USERNAME=$(yq -r '.channels.telegram.bot_username // ""' "$CONFIG_FILE")
    if [[ -n "$TG_USERNAME" ]]; then
        pass "Telegram bot: @$TG_USERNAME"
    fi

    # Gmail: just note it requires interactive OAuth
    GMAIL=$(yq -r '.channels.gmail.email // ""' "$CONFIG_FILE")
    if [[ -n "$GMAIL" ]]; then
        warn "Gmail ($GMAIL) requires interactive OAuth during provisioning"
    fi
fi

# ---------------------------------------------------------------
# Summary
# ---------------------------------------------------------------
echo ""
echo -e "${CYAN}${BOLD}=== Summary ===${NC}"
echo ""
echo -e "  ${GREEN}${PASS} passed${NC}  ${RED}${FAIL} failed${NC}  ${YELLOW}${WARN} warnings${NC}"
echo ""

if [[ $FAIL -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}Ready to provision!${NC}"
    echo "  Run: ./create-agent.sh $CONFIG_FILE"
else
    echo -e "  ${RED}${BOLD}Fix the ${FAIL} failure(s) above before running create-agent.sh${NC}"
fi
echo ""
