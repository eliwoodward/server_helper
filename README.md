# Server Helper

A single-file CLI agent that drops onto any Linux box and gets to work. Choose your model (Claude or GPT), and it runs commands, reads files, searches your filesystem, and iterates autonomously until the job is done.

Built because copy-pasting between an LLM and a terminal felt like being a slow API. Now the model just has the shell.

---

## Features

- **Multi-provider model selection** — pick from Anthropic (Claude Sonnet 4.6, Opus 4.7, Haiku 4.5) or OpenAI (GPT-5.5, GPT-5.4, GPT-4.1, and their mini variants) at startup
- **Encrypted API key storage** — keys are encrypted with Fernet using a machine-derived PBKDF2 key, not stored in plaintext
- **System profiling** — on first run, collects host info (OS, CPU, memory, services, ports, Docker, firewall, etc.) and writes `system_profile.md` so the model knows what box it's on
- **Agentic tool loop** — up to 25 tool calls per turn with bash, file read/write, and filesystem search
- **One file, no framework** — drop it on a box, run it, done
- **Context management** — automatic pruning and trimming to keep long sessions from blowing up
- **Switch models mid-session** — `/model` command lets you swap providers without restarting

## Requirements

- Python 3.10+
- Linux (tested on Ubuntu 22.04/24.04, Debian 12, RHEL 9, Amazon Linux 2023)
- An API key from [Anthropic](https://console.anthropic.com/) and/or [OpenAI](https://platform.openai.com/)

Dependencies (`requests` and `cryptography`) are auto-installed on first run if missing.

## Quick Start

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/server-helper.git
cd server-helper

# Run it
python3 server_helper.py
```

On first launch:

1. **System profile** — the script scans the box (hostname, OS, CPU, memory, services, ports, Docker, firewall, etc.) and saves the results to `~/.server_helper/system_profile.md`
2. **Model selection** — pick a model from the numbered menu
3. **API key** — if no key is stored for that provider, you'll be prompted (input is hidden, key is encrypted and saved)
4. **Connectivity test** — a quick test request confirms the key and model work
5. **You're in** — start asking

## Usage

### Interactive mode

```bash
python3 server_helper.py
```

### Single question mode

```bash
python3 server_helper.py --ask "what services are running and which ports are open"
```

### Limit tool rounds

```bash
python3 server_helper.py --max-rounds 10
```

## What the model selection looks like

```
  Select a model
  ────────────────────────────────────────────────

  Anthropic
    ● 1  Claude Sonnet 4.6        Speed + intelligence, 1M ctx ($3/$15)
    ● 2  Claude Opus 4.7          Most intelligent ($5/$25)
    ● 3  Claude Haiku 4.5         Fastest, cheapest ($1/$5)

  OpenAI
    ○ 4  GPT-5.5                  Frontier reasoning, 1M ctx ($5/$30)
    ○ 5  GPT-5.4                  Flagship, 1M ctx ($2.50/$15)
    ○ 6  GPT-5.4 Mini             Fast & efficient ($0.75)
    ○ 7  GPT-4.1                  Best tool-calling, 1M ctx, cheap
    ○ 8  GPT-4.1 Mini             Tool-calling, lowest latency

  ● = API key on file   ○ = key needed
```

## Commands

| Command | What it does |
|---------|-------------|
| `/model` | Switch model or provider mid-session |
| `/clear` | Reset conversation history |
| `/cost` | Show token usage for the session |
| `/key` | Update API key for the current provider |
| `/help` | Show help |
| `/quit` | Exit |
| `update md` | Re-scan the system and refresh the profile |

## How it works

The script gives the model four tools:

| Tool | Description |
|------|-------------|
| `bash` | Run any shell command (full system access as the running user) |
| `read_file` | Read any file or list a directory |
| `write_file` | Create or overwrite files anywhere the user has permissions |
| `search_files` | Find files by name (glob) or search content (grep) |

The model chains these tools in an agentic loop — if the first search doesn't find what it needs, it tries different terms, reads what it finds, and iterates. Up to 25 rounds per turn by default.

## API Key Storage

Keys are **not** stored in plaintext. The script uses:

- `cryptography.fernet.Fernet` for symmetric encryption
- A key derived via **PBKDF2-HMAC-SHA256** (480,000 iterations) from `/etc/machine-id` + a random per-install salt
- Everything stored in `~/.server_helper/` with `0600` permissions

This means keys are encrypted at rest and tied to the machine. Moving `keys.enc` to a different box won't decrypt it.

You can also skip the encrypted store entirely by setting environment variables:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export OPENAI_API_KEY=sk-proj-...
python3 server_helper.py
```

Environment variables take priority over the encrypted store.

## System Profile

On first run, the script collects:

- Hostname, OS, kernel
- CPU, memory, disk
- Network interfaces, public IP, gateway, DNS
- Listening ports, running services
- Docker containers
- Users, cron jobs, recent logins
- Firewall status, installed package managers
- Key directories (`/opt/`, `/srv/`, `/var/www/`, `/var/log/`)

This is saved to `~/.server_helper/system_profile.md` and injected into the system prompt so the model has context about what it's working with. A compact summary also prints in the startup banner.

Say **`update md`** in chat anytime to re-scan and refresh.

## What user should it run as?

It runs as whatever user launches it. No root requirement.

- **As your normal user** — works fine for development, file management, project work. Some profiling commands may return "permission denied" on system files, which is harmless.
- **As root** — gives the model full system access for sysadmin tasks, threat hunting, service management, log analysis. You're trusting the model with a root shell, so use judgment.
- **Middle ground** — run as a non-root user in the `docker`, `adm`, and `systemd-journal` groups for broad read access without full root.

## File structure

```
server-helper/
├── server_helper.py     # The entire tool (single file)
├── README.md
├── LICENSE
├── requirements.txt
├── .gitignore
└── CHANGELOG.md
```

At runtime, the script creates:

```
~/.server_helper/
├── keys.enc             # Encrypted API keys
├── .salt                # Random salt for key derivation
├── system_profile.md    # Auto-generated system profile
└── input_history        # Readline history
```

## Contributing

Issues and PRs welcome. This is a single-file tool by design — please keep it that way.

## License

MIT — see [LICENSE](LICENSE).
