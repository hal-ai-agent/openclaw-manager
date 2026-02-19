# OpenClaw Manager

Provision a new OpenClaw agent on DigitalOcean from a Linux command line. Secrets go in 1Password.

## End-to-End Walkthrough

### Step 0: Prerequisites (one-time setup)

You need these tools installed and authenticated on the machine running the manager:

| Tool | Check | Setup |
|------|-------|-------|
| **doctl** | `doctl compute ssh-key list` | `doctl auth init` with your [DO API token](https://cloud.digitalocean.com/account/api/tokens) |
| **op** | `op vault list` | Set `OP_SERVICE_ACCOUNT_TOKEN` env var ([service account setup](https://developer.1password.com/docs/service-accounts/)) |
| **jq** | `jq --version` | `apt-get install jq` |
| **yq** | `yq --version` | Installed automatically by `create-agent.sh` |
| **ssh** | `ssh -V` | Built into Linux |

If you don't have these, run the installer first:

```bash
curl -fsSL https://raw.githubusercontent.com/hal-ai-agent/openclaw-manager/main/install.sh | bash
```

#### DigitalOcean API Token Scopes

When creating a DO API token at [cloud.digitalocean.com/account/api/tokens](https://cloud.digitalocean.com/account/api/tokens):

| Scope | Permissions needed |
|-------|-------------------|
| **Droplet** | create, read, update, delete, admin |
| **SSH Key** | read (minimum) |

> When you click "Create Token", DigitalOcean may prompt you to add additional required permissions. Accept them.

#### SSH Key in DigitalOcean

You need at least one SSH key registered with DigitalOcean. Check with:

```bash
doctl compute ssh-key list
```

If empty, add one:

```bash
# Generate a key if you don't have one
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519

# Add to DigitalOcean
doctl compute ssh-key create my-key --public-key-file ~/.ssh/id_ed25519.pub
```

#### 1Password

Your 1Password vault (default: `AI-Agents`) should contain:
- An Anthropic API key (the script will search for any item with "anthropic" in the title, or you can specify the exact item name in the config)

---

### Step 1: Pre-flight manual steps

Before running the script, you need to do these things by hand:

#### 1a. Create a Telegram bot (if using Telegram)

1. Open Telegram and message [@BotFather](https://t.me/BotFather)
2. Send `/newbot`
3. Choose a display name (e.g., "Eva AI")
4. Choose a username ending in `bot` (e.g., `eva_dimagi_bot`)
5. BotFather gives you a token like `123456789:ABCdefGHIjklMNO...`
6. **Save the token** -- you'll enter it in the config file

Optional but recommended:
- Send `/setprivacy` to BotFather, select your bot, choose "Disable" (lets the bot see group messages)
- Send `/setdescription` to set what users see before starting a chat

#### 1b. Create a Gmail account (if using Gmail)

If the agent needs email, create a Google Workspace or Gmail account for it. You'll also need:
- A Google Cloud project with Gmail and Pub/Sub APIs enabled
- OAuth credentials (Client ID + Secret) for `gog`

> Gmail setup is guided interactively during provisioning -- the script will tell you when to SSH in and complete the OAuth flow.

---

### Step 2: Create the agent config

Copy the template and fill it in:

```bash
cp templates/agent-config.yaml my-agent.yaml
```

Edit `my-agent.yaml`. Here's what each field means:

```yaml
# --- Required ---
name: Eva                          # Agent name. Used for 1Password prefixes and hostname.
                                   # Example: secrets stored as "Eva - Anthropic API Key"

# --- Infrastructure (all have defaults) ---
hostname: openclaw-eva             # Droplet hostname. Default: openclaw-<name lowercase>
region: nyc3                       # DO region. Default: nyc3
                                   # Options: nyc1, nyc3, sfo3, lon1, ams3, sgp1, fra1
size: s-1vcpu-2gb                  # Droplet size. Default: s-1vcpu-2gb ($12/mo)
                                   # Cheapest: s-1vcpu-1gb ($6/mo, needs swap)
ssh_key_name: ""                   # DO SSH key name. Leave empty to use first available.

# --- AI ---
model: anthropic/claude-sonnet-4-20250514   # Default model for the agent

# --- 1Password ---
vault: AI-Agents                   # Vault for storing agent secrets
anthropic_key_item: ""             # Exact 1Password item title for the Anthropic key.
                                   # Leave empty to auto-find (searches for "anthropic" in vault).

# --- Channels (delete sections you don't need) ---
channels:
  telegram:
    bot_name: "Eva AI"             # Display name (for documentation only)
    bot_username: eva_dimagi_bot   # The @username you chose in BotFather
    bot_token_item: ""             # 1Password item title if token is already stored.
                                   # Leave empty -- the script will prompt you to paste it.

  gmail:
    email: eva@example.com         # Gmail address for the agent
    gcp_project: my-gcp-project    # Google Cloud project ID

# --- Post-provision ---
pair_with: ""                      # Telegram user ID to auto-pair with.
                                   # Find yours: message @userinfobot on Telegram.
test_prompt: "Say hello in 3 words"  # Prompt to verify the agent works.
```

**Minimal config** (just infrastructure, no channels):

```yaml
name: TestBot
size: s-1vcpu-1gb
vault: AI-Agents
test_prompt: "Say hello in 3 words"
```

**Typical config** (Telegram only):

```yaml
name: Eva
region: nyc3
size: s-1vcpu-2gb
model: anthropic/claude-sonnet-4-20250514
vault: AI-Agents

channels:
  telegram:
    bot_name: "Eva AI"
    bot_username: eva_dimagi_bot

test_prompt: "Say hello in 3 words"
```

---

### Step 3: Run it

```bash
./create-agent.sh my-agent.yaml
```

The script will:

1. **Preflight** -- verify doctl, op, jq, yq, ssh are available and authenticated
2. **Parse config** -- read your YAML and show a summary
3. **Resolve SSH key** -- find or select the SSH key from DigitalOcean
4. **Resolve secrets** -- pull Anthropic key from 1Password. If a Telegram token isn't in 1Password, **it will prompt you to paste it**.
5. **Create droplet** -- provisions the droplet and waits for SSH (1-3 minutes)
6. **Install OpenClaw** -- updates system, adds swap, installs Node.js, Tailscale, OpenClaw (~5 minutes)
7. **Configure OpenClaw** -- runs onboarding, sets the model
8. **Set up Telegram** -- configures the bot token (if provided)
9. **Gmail** -- if configured, tells you to SSH in and complete OAuth manually
10. **Upload workspace files** -- copies SOUL.md and any custom files
11. **Store secrets** -- creates 1Password entries prefixed with the agent name
12. **Verify** -- starts the gateway and runs the test prompt

#### What you'll see

```
=== Step 0: Preflight checks
  OK: doctl authenticated
  OK: op authenticated

=== Step 1: Parse agent config
  Agent:    Eva
  Hostname: openclaw-eva
  Region:   nyc3
  ...

=== Step 4: Create DigitalOcean droplet
  Creating s-1vcpu-2gb droplet in nyc3...
  OK: Droplet created: openclaw-eva (143.198.x.x)

=== Step 5: Install OpenClaw
  >>> Updating system...
  >>> Installing Node.js 22...
  >>> Installing OpenClaw...
  OK: OpenClaw installed: 0.x.x

...

========================================
  Agent 'Eva' provisioned!
========================================

  Droplet:   openclaw-eva (143.198.x.x)
  Telegram:  @eva_dimagi_bot
  SSH:       ssh root@143.198.x.x
```

#### Interactive prompts during the run

| When | What you'll be asked | What to enter |
|------|---------------------|---------------|
| Step 3 (secrets) | Telegram bot token | Paste the token from BotFather |
| Step 8 (Gmail) | Complete OAuth flow | SSH into droplet in another terminal, run the command shown |

Everything else is automated.

---

### Step 4: After provisioning

1. **Test the bot** -- message your bot on Telegram
2. **Pair** -- the bot will ask you to pair. Approve it.
3. **SSH access** -- `ssh root@<droplet-ip>`
4. **Logs** -- `ssh root@<droplet-ip> openclaw logs --follow`
5. **Control UI** -- `ssh -L 18789:localhost:18789 root@<droplet-ip>` then open http://localhost:18789

---

### Resume

If the script is interrupted at any point, just run it again:

```bash
./create-agent.sh my-agent.yaml
# or
./create-agent.sh --resume Eva
```

State is saved to `~/.openclaw-manager/Eva/state.json`. Each step checks if it already completed and skips forward.

---

### Cleanup

To delete a test agent:

```bash
# Delete the droplet
doctl compute droplet list  # find the ID
doctl compute droplet delete <id>

# Delete 1Password entries
op item list --vault AI-Agents --tags testbot  # list entries
op item delete "<item-id>" --vault AI-Agents   # delete each

# Delete local state
rm -rf ~/.openclaw-manager/TestBot
```

---

## Files

| File | Description |
|------|-------------|
| `install.sh` | Installs manager prerequisites (doctl, op, jq, yq) |
| `create-agent.sh` | Main provisioning script |
| `templates/agent-config.yaml` | Config template with all options and comments |
| `templates/SOUL.md` | Default personality template for new agents |
| `config.json` | Rig metadata (for AI Foundry catalog) |

## Cost

| Item | Cost |
|------|------|
| s-1vcpu-1gb droplet | $6/month |
| s-1vcpu-2gb droplet | $12/month |
| Anthropic API usage | ~$5-20/month |
