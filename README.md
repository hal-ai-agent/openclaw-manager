# OpenClaw Manager

Programmatically provision new OpenClaw agents on DigitalOcean with secrets managed in 1Password.

## What This Rig Does

- Creates a DigitalOcean droplet from a YAML config file
- Installs OpenClaw with swap optimization and systemd
- Configures channels (Telegram automated, Gmail guided)
- Stores all secrets in 1Password with agent-name prefixes
- Supports resume if interrupted at any step
- Designed for use by an AI manager agent or a human with CLI access

## Prerequisites

| Requirement | Description |
|-------------|-------------|
| Linux machine | The manager runs from an existing Linux box |
| doctl | DigitalOcean CLI, authenticated |
| op | 1Password CLI, authenticated |
| SSH key | Registered with DigitalOcean |
| Anthropic API key | In 1Password or entered at runtime |

## Quick Start

```bash
# Install manager tools
curl -fsSL https://raw.githubusercontent.com/hal-ai-agent/ai-foundry/main/rigs/openclaw-manager/install.sh | bash

# Copy and edit the agent config
cp ~/.openclaw-manager/rig/templates/agent-config.yaml my-agent.yaml
# Edit my-agent.yaml with your agent's details

# Create the agent
~/.openclaw-manager/rig/create-agent.sh my-agent.yaml
```

## Agent Config

The config file defines everything about the new agent:

```yaml
name: Eva
hostname: openclaw-eva
region: nyc3
size: s-1vcpu-2gb
model: anthropic/claude-sonnet-4-20250514
vault: AI-Agents

channels:
  telegram:
    bot_username: eva_dimagi_bot
  gmail:
    email: eva@example.com
    gcp_project: my-gcp-project
```

See `templates/agent-config.yaml` for the full schema with comments.

## What Gets Created

### DigitalOcean
- Ubuntu 24.04 droplet with swap, Node.js 22, Tailscale, OpenClaw
- Systemd service for always-on operation

### 1Password (in the configured vault)
All entries are prefixed with the agent name:
- `<Name> - Anthropic API Key`
- `<Name> - Telegram Bot Token`
- `<Name> - Droplet Info` (IP, region, size, etc.)

### Channels
- **Telegram**: Fully automated if you provide the bot token
- **Gmail**: Guided setup (requires OAuth consent flow via SSH)

## Resume Support

If the script is interrupted, run it again with the same config or use `--resume`:

```bash
./create-agent.sh --resume Eva
```

State is saved to `~/.openclaw-manager/<agent-name>/state.json`.

## Cost

| Item | Cost |
|------|------|
| DigitalOcean droplet (2GB) | $12/month |
| Anthropic API usage | ~$5-20/month |
| **Total** | **~$17-32/month** |

## Files

| File | Description |
|------|-------------|
| `install.sh` | Installs manager prerequisites |
| `create-agent.sh` | Main provisioning script |
| `templates/agent-config.yaml` | Example agent configuration |
| `templates/SOUL.md` | Default personality template |

## DigitalOcean API Token Scopes

When creating a DO API token, you need these scopes:

| Scope | Permissions | Why |
|-------|-------------|-----|
| **Droplet** | create, read, update, delete, admin | Create and manage agent droplets |
| **SSH Key** | read (minimum) | List SSH keys to inject into new droplets |

> **Note:** When you click "Create Token", DigitalOcean may prompt you to add additional required permissions. Accept those -- they are dependencies of the scopes above.

The `account:read` scope is **not** required. The manager verifies auth by listing SSH keys instead.

## Security Notes

- Secrets are stored in 1Password, not on disk
- SSH keys are managed via DigitalOcean (never stored locally)
- The manager needs read access to the 1Password vault for shared secrets
- Each agent gets its own prefixed entries in the shared vault
