#!/usr/bin/env bash
#
# OpenClaw Manager -- Preflight Check
#
# Verifies all prerequisites are in place before running create-agent.sh.
# Run this first to catch missing tools, auth issues, or config problems.
#
# Usage:
#   ./preflight.sh                    # Check tools + auth only
#   ./preflight.sh my-agent.yaml      # Also validate the agent config
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

pass() { echo -e "  ${GREEN}PASS${NC}  $1"; ((PASS++)); }
fail() { echo -e "  ${RED}FAIL${NC}  $1"; ((FAIL++)); }
warn() { echo -e "  ${YELLOW}WARN${NC}  $1"; ((WARN++)); }
info() { echo -e "        $1"; }

# ---------------------------------------------------------------
# Section 1: Tools
# ---------------------------------------------------------------
echo ""
echo -e "${CYAN}${BOLD}=== Tools ===${NC}"
echo ""

# ssh
if command -v ssh &>/dev/null; then
    pass "ssh installed"
else
    fail "ssh not found"
    info "Install: apt-get install openssh-client"
fi

# jq
if command -v jq &>/dev/null; then
    pass "jq installed ($(jq --version 2>&1))"
else
    fail "jq not found"
    info "Install: apt-get install jq"
fi

# yq
if command -v yq &>/dev/null; then
    pass "yq installed ($(yq --version 2>&1 | head -1))"
else
    warn "yq not found (create-agent.sh will install it automatically)"
    info "Manual install: https://github.com/mikefarah/yq/releases"
fi

# doctl
if command -v doctl &>/dev/null; then
    DOCTL_VER=$(doctl version 2>&1 | head -1)
    pass "doctl installed (${DOCTL_VER})"
else
    fail "doctl not found"
    info "Install: https://docs.digitalocean.com/reference/doctl/how-to/install/"
    info "Quick:   curl -sL https://github.com/digitalocean/doctl/releases/download/v1.104.0/doctl-1.104.0-linux-amd64.tar.gz | tar xz -C /usr/local/bin"
fi

# op
if command -v op &>/dev/null; then
    pass "op installed ($(op --version 2>/dev/null))"
else
    fail "op (1Password CLI) not found"
    info "Install: https://developer.1password.com/docs/cli/get-started/"
fi

# ---------------------------------------------------------------
# Section 2: Authentication
# ---------------------------------------------------------------
echo ""
echo -e "${CYAN}${BOLD}=== Authentication ===${NC}"
echo ""

# doctl auth
if command -v doctl &>/dev/null; then
    if doctl compute ssh-key list --no-header &>/dev/null 2>&1; then
        pass "doctl authenticated (can list SSH keys)"
    else
        fail "doctl not authenticated or token missing SSH Key scope"
        info "Fix: doctl auth init --access-token <your-token>"
        info "Token needs: Droplet (all) + SSH Key (read) scopes"
        info "Create at: https://cloud.digitalocean.com/account/api/tokens"
    fi
else
    fail "doctl not installed (skipping auth check)"
fi

# op auth
if command -v op &>/dev/null; then
    if [[ -n "${OP_SERVICE_ACCOUNT_TOKEN:-}" ]]; then
        if op whoami &>/dev/null 2>&1; then
            OP_URL=$(op whoami --format json 2>/dev/null | jq -r '.url // "unknown"')
            pass "op authenticated via service account (${OP_URL})"
        else
            fail "OP_SERVICE_ACCOUNT_TOKEN is set but op whoami failed"
            info "The token may be invalid or expired"
        fi
    else
        if op whoami &>/dev/null 2>&1; then
            pass "op authenticated (user session)"
        else
            fail "op not authenticated"
            info "Option 1 (recommended): Set OP_SERVICE_ACCOUNT_TOKEN env var"
            info "Option 2: Run 'eval \$(op signin)'"
        fi
    fi
else
    fail "op not installed (skipping auth check)"
fi

# ---------------------------------------------------------------
# Section 3: DigitalOcean Resources
# ---------------------------------------------------------------
echo ""
echo -e "${CYAN}${BOLD}=== DigitalOcean ===${NC}"
echo ""

if command -v doctl &>/dev/null && doctl compute ssh-key list --no-header &>/dev/null 2>&1; then
    SSH_KEY_COUNT=$(doctl compute ssh-key list --format ID --no-header 2>/dev/null | wc -l)
    if [[ $SSH_KEY_COUNT -gt 0 ]]; then
        FIRST_KEY_NAME=$(doctl compute ssh-key list --format Name --no-header 2>/dev/null | head -1)
        pass "SSH keys in DigitalOcean: ${SSH_KEY_COUNT} (first: ${FIRST_KEY_NAME})"
    else
        fail "No SSH keys registered in DigitalOcean"
        info "Add one: doctl compute ssh-key create my-key --public-key-file ~/.ssh/id_ed25519.pub"
        info "Or generate first: ssh-keygen -t ed25519"
    fi

    # Test droplet create permission with a dry check (list existing)
    if doctl compute droplet list --no-header &>/dev/null 2>&1; then
        DROPLET_COUNT=$(doctl compute droplet list --format ID --no-header 2>/dev/null | wc -l)
        pass "Droplet access works (${DROPLET_COUNT} existing droplets)"
    else
        fail "Cannot list droplets -- token may be missing Droplet scope"
        info "Token needs Droplet scope with: create, read, update, delete, admin"
    fi
else
    warn "Skipping DigitalOcean checks (doctl not authenticated)"
fi

# ---------------------------------------------------------------
# Section 4: 1Password Vault
# ---------------------------------------------------------------
echo ""
echo -e "${CYAN}${BOLD}=== 1Password ===${NC}"
echo ""

if command -v op &>/dev/null && op whoami &>/dev/null 2>&1; then
    # Check vault access
    DEFAULT_VAULT="AI-Agents"
    if op vault get "$DEFAULT_VAULT" &>/dev/null 2>&1; then
        ITEM_COUNT=$(op item list --vault="$DEFAULT_VAULT" --format json 2>/dev/null | jq 'length')
        pass "Vault '${DEFAULT_VAULT}' accessible (${ITEM_COUNT} items)"
    else
        warn "Default vault '${DEFAULT_VAULT}' not found"
        info "Available vaults:"
        op vault list --format json 2>/dev/null | jq -r '.[].name' | while read -r v; do
            info "  - $v"
        done
        info "Set a different vault in your agent config: vault: <name>"
    fi

    # Check for Anthropic key
    ANTHROPIC_ITEM=$(op item list --vault="$DEFAULT_VAULT" --format json 2>/dev/null | jq -r '[.[] | select(.title | test("anthropic"; "i"))][0].title // ""')
    if [[ -n "$ANTHROPIC_ITEM" ]]; then
        pass "Anthropic API key found: '${ANTHROPIC_ITEM}'"
    else
        fail "No item with 'anthropic' in the title found in vault '${DEFAULT_VAULT}'"
        info "Store one: op item create --category=apiCredential --title='Anthropic API Key' --vault='${DEFAULT_VAULT}' 'credential=sk-ant-...'"
        info "Or specify anthropic_key_item in your agent config"
    fi
else
    warn "Skipping 1Password checks (not authenticated)"
fi

# ---------------------------------------------------------------
# Section 5: Agent Config (optional)
# ---------------------------------------------------------------
CONFIG_FILE="${1:-}"

if [[ -n "$CONFIG_FILE" ]]; then
    echo ""
    echo -e "${CYAN}${BOLD}=== Agent Config: ${CONFIG_FILE} ===${NC}"
    echo ""

    if [[ ! -f "$CONFIG_FILE" ]]; then
        fail "Config file not found: ${CONFIG_FILE}"
    else
        pass "Config file exists"

        if ! command -v yq &>/dev/null; then
            warn "yq not installed -- cannot validate config contents"
        else
            # Name (required)
            NAME=$(yq -r '.name // ""' "$CONFIG_FILE")
            if [[ -n "$NAME" ]]; then
                pass "Agent name: ${NAME}"
            else
                fail "Agent name is required (set 'name:' in config)"
            fi

            # Region
            REGION=$(yq -r '.region // "nyc3"' "$CONFIG_FILE")
            pass "Region: ${REGION}"

            # Size
            SIZE=$(yq -r '.size // "s-1vcpu-2gb"' "$CONFIG_FILE")
            pass "Size: ${SIZE}"

            # Model
            MODEL=$(yq -r '.model // "anthropic/claude-sonnet-4-20250514"' "$CONFIG_FILE")
            pass "Model: ${MODEL}"

            # Vault
            VAULT=$(yq -r '.vault // "AI-Agents"' "$CONFIG_FILE")
            if command -v op &>/dev/null && op vault get "$VAULT" &>/dev/null 2>&1; then
                pass "Vault: ${VAULT} (accessible)"
            else
                warn "Vault: ${VAULT} (cannot verify access)"
            fi

            # Telegram
            TG_USERNAME=$(yq -r '.channels.telegram.bot_username // ""' "$CONFIG_FILE")
            if [[ -n "$TG_USERNAME" ]]; then
                pass "Telegram bot: @${TG_USERNAME}"
                TG_TOKEN_ITEM=$(yq -r '.channels.telegram.bot_token_item // ""' "$CONFIG_FILE")
                if [[ -n "$TG_TOKEN_ITEM" ]]; then
                    if command -v op &>/dev/null && op item get "$TG_TOKEN_ITEM" --vault="$VAULT" &>/dev/null 2>&1; then
                        pass "Telegram token found in 1Password: '${TG_TOKEN_ITEM}'"
                    else
                        warn "Telegram token item '${TG_TOKEN_ITEM}' not found in vault -- script will prompt"
                    fi
                else
                    info "Telegram token: will prompt during setup (create bot via @BotFather first)"
                fi
            fi

            # Gmail
            GMAIL=$(yq -r '.channels.gmail.email // ""' "$CONFIG_FILE")
            if [[ -n "$GMAIL" ]]; then
                pass "Gmail: ${GMAIL}"
                GCP=$(yq -r '.channels.gmail.gcp_project // ""' "$CONFIG_FILE")
                if [[ -n "$GCP" ]]; then
                    pass "GCP project: ${GCP}"
                else
                    warn "Gmail configured but no gcp_project set"
                fi
                info "Gmail requires interactive OAuth during setup"
            fi
        fi
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
    if [[ -z "$CONFIG_FILE" ]]; then
        echo "  Run:  ./preflight.sh my-agent.yaml   (to also validate your config)"
        echo "  Then: ./create-agent.sh my-agent.yaml"
    else
        echo "  Run:  ./create-agent.sh ${CONFIG_FILE}"
    fi
else
    echo -e "  ${RED}${BOLD}Fix the ${FAIL} failure(s) above before running create-agent.sh${NC}"
fi
echo ""
