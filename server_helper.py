#!/usr/bin/env python3
"""
Server Helper — Multi-Provider Agentic CLI Assistant
=====================================================
An interactive CLI agent that runs on your server and helps you find,
build, code, investigate, and automate. Supports both Anthropic and
OpenAI models with encrypted API key storage and persistent system
profiling.

Capabilities:
  - Choose from Anthropic (Claude) and OpenAI (GPT/o-series) models
  - Encrypted API key storage per provider (Fernet + machine-derived key)
  - Automatic system profiling on first run (creates system_profile.md)
  - Execute bash commands, read/write files, search filesystem
  - Iterates autonomously up to 25 tool rounds per turn
  - Maintains conversation history across the session

Usage:
  python3 server_helper.py
  python3 server_helper.py --ask "show me all running services and open ports"
  python3 server_helper.py --max-rounds 10

First run: collects system info → writes ~/.server_helper/system_profile.md
Subsequent runs: reads profile and shows a summary at startup.
Say "update md" in chat to refresh the profile if things have changed.
"""

import os, sys, json, subprocess, readline, argparse, signal, hashlib, base64, getpass
from pathlib import Path
from datetime import datetime

# ── Dependency bootstrap ─────────────────────────────────────────────

def _ensure_deps():
    """Install missing dependencies quietly."""
    required = {"requests": "requests", "cryptography": "cryptography"}
    missing = []
    for mod, pkg in required.items():
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"  [*] Installing dependencies: {', '.join(missing)}")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet",
             "--break-system-packages", *missing],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

_ensure_deps()

import requests
from cryptography.fernet import Fernet

# ══════════════════════════════════════════════════════════════════════
#  CONSTANTS & CONFIG
# ══════════════════════════════════════════════════════════════════════

CONFIG_DIR       = Path.home() / ".server_helper"
KEYS_FILE        = CONFIG_DIR / "keys.enc"
SALT_FILE        = CONFIG_DIR / ".salt"
PROFILE_FILE     = CONFIG_DIR / "system_profile.md"
HISTORY_FILE     = CONFIG_DIR / "input_history"

MAX_TOKENS       = 8192
DEFAULT_MAX_ROUNDS = 25
BASH_TIMEOUT     = 120
MAX_OUTPUT_CHARS  = 8000
MAX_CONTEXT_CHARS = 120000

# ── Palette ──────────────────────────────────────────────────────────
R  = '\033[0;31m';  G  = '\033[0;32m';  Y  = '\033[1;33m'
C  = '\033[0;36m';  B  = '\033[1m';     RS = '\033[0m'
DIM = '\033[2m';    MAG = '\033[0;35m'; BLU = '\033[0;34m'
WHT = '\033[1;37m'; UND = '\033[4m'
# Box-drawing
H = '─'; V = '│'; TL = '╭'; TR = '╮'; BL = '╰'; BR = '╯'

# ══════════════════════════════════════════════════════════════════════
#  MODEL REGISTRY
# ══════════════════════════════════════════════════════════════════════

PROVIDERS = {
    "anthropic": {
        "name": "Anthropic",
        "api_url": "https://api.anthropic.com/v1/messages",
        "key_env": "ANTHROPIC_API_KEY",
        "key_prefix": "sk-ant-",
        "models": [
            {"id": "claude-sonnet-4-6",          "label": "Claude Sonnet 4.6",  "desc": "Speed + intelligence, 1M ctx ($3/$15)"},
            {"id": "claude-opus-4-7",            "label": "Claude Opus 4.7",    "desc": "Most intelligent ($5/$25)"},
            {"id": "claude-haiku-4-5-20251001",  "label": "Claude Haiku 4.5",   "desc": "Fastest, cheapest ($1/$5)"},
        ],
    },
    "openai": {
        "name": "OpenAI",
        "api_url": "https://api.openai.com/v1/chat/completions",
        "key_env": "OPENAI_API_KEY",
        "key_prefix": "sk-",
        "models": [
            {"id": "gpt-5.5",        "label": "GPT-5.5",        "desc": "Frontier reasoning, 1M ctx ($5/$30)"},
            {"id": "gpt-5.4",        "label": "GPT-5.4",        "desc": "Flagship, 1M ctx ($2.50/$15)"},
            {"id": "gpt-5.4-mini",   "label": "GPT-5.4 Mini",   "desc": "Fast & efficient ($0.75)"},
            {"id": "gpt-4.1",        "label": "GPT-4.1",        "desc": "Best tool-calling, 1M ctx, cheap"},
            {"id": "gpt-4.1-mini",   "label": "GPT-4.1 Mini",   "desc": "Tool-calling, lowest latency"},
        ],
    },
}

# ══════════════════════════════════════════════════════════════════════
#  ENCRYPTED KEY STORAGE
# ══════════════════════════════════════════════════════════════════════

def _derive_fernet_key() -> bytes:
    """
    Derive a deterministic Fernet key from the machine's identity.
    Uses /etc/machine-id (Linux) + a random salt stored alongside
    the key file. The salt is unique per install so the same machine-id
    doesn't produce a predictable key if the salt file leaks separately.
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)

    # Machine identity
    machine_id = b"server-helper-fallback"
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        p = Path(path)
        if p.exists():
            machine_id = p.read_bytes().strip()
            break

    # Per-install salt (created once)
    if SALT_FILE.exists():
        salt = SALT_FILE.read_bytes()
    else:
        salt = os.urandom(32)
        SALT_FILE.write_bytes(salt)
        os.chmod(str(SALT_FILE), 0o600)

    raw = hashlib.pbkdf2_hmac("sha256", machine_id, salt, 480_000, dklen=32)
    return base64.urlsafe_b64encode(raw)


def load_all_keys() -> dict:
    """Load and decrypt the key store. Returns {provider: api_key}."""
    if not KEYS_FILE.exists():
        return {}
    try:
        f = Fernet(_derive_fernet_key())
        data = f.decrypt(KEYS_FILE.read_bytes())
        return json.loads(data)
    except Exception:
        return {}


def save_all_keys(keys: dict):
    """Encrypt and save the full key store."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    f = Fernet(_derive_fernet_key())
    KEYS_FILE.write_bytes(f.encrypt(json.dumps(keys).encode()))
    os.chmod(str(KEYS_FILE), 0o600)


def get_key(provider: str) -> str | None:
    """Get API key for a provider: env var first, then encrypted store."""
    env_var = PROVIDERS[provider]["key_env"]
    val = os.environ.get(env_var)
    if val:
        return val
    return load_all_keys().get(provider)


def prompt_and_save_key(provider: str) -> str:
    """Interactive prompt to collect and store an API key."""
    info = PROVIDERS[provider]
    print(f"\n  {Y}{B}API KEY SETUP — {info['name']}{RS}")
    print(f"  {DIM}Keys are encrypted with a machine-derived key and stored in:{RS}")
    print(f"  {DIM}{KEYS_FILE}{RS}\n")

    key = getpass.getpass(f"  {C}Paste {info['name']} API key (hidden):{RS} ").strip()
    if not key:
        print(f"  {R}✘ No key provided.{RS}")
        sys.exit(1)

    expected = info["key_prefix"]
    if not key.startswith(expected):
        yn = input(f"  {Y}Key doesn't start with '{expected}'. Use anyway? (y/n):{RS} ").strip().lower()
        if yn not in ("y", "yes"):
            print(f"  {R}✘ Aborted.{RS}")
            sys.exit(1)

    keys = load_all_keys()
    keys[provider] = key
    save_all_keys(keys)

    masked = key[:8] + "•" * 12 + key[-4:]
    print(f"  {G}✔ Key encrypted & saved{RS}")
    print(f"  {DIM}{masked}{RS}\n")
    return key


# ══════════════════════════════════════════════════════════════════════
#  CONNECTIVITY TEST
# ══════════════════════════════════════════════════════════════════════

def test_connectivity(provider: str, model_id: str, api_key: str) -> bool:
    """Send a tiny request to verify the API key + model work."""
    print(f"  {DIM}Testing connectivity to {PROVIDERS[provider]['name']}…{RS}", end="", flush=True)

    try:
        if provider == "anthropic":
            resp = requests.post(
                PROVIDERS[provider]["api_url"],
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": model_id,
                    "max_tokens": 32,
                    "messages": [{"role": "user", "content": "Reply with the word CONNECTED."}],
                },
                timeout=30,
            )
        else:  # openai
            resp = requests.post(
                PROVIDERS[provider]["api_url"],
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model_id,
                    "max_completion_tokens": 32,
                    "messages": [{"role": "user", "content": "Reply with the word CONNECTED."}],
                },
                timeout=30,
            )

        if resp.status_code == 200:
            print(f" {G}✔ Connected{RS}")
            return True
        else:
            body = resp.text[:300]
            print(f" {R}✘ HTTP {resp.status_code}{RS}")
            print(f"  {DIM}{body}{RS}")
            return False
    except requests.exceptions.RequestException as e:
        print(f" {R}✘ {e}{RS}")
        return False


# ══════════════════════════════════════════════════════════════════════
#  SYSTEM PROFILING
# ══════════════════════════════════════════════════════════════════════

PROFILE_COMMANDS = [
    ("Hostname",            "hostname -f 2>/dev/null || hostname"),
    ("OS / Kernel",         "cat /etc/os-release 2>/dev/null | head -4; echo '---'; uname -r"),
    ("Uptime",              "uptime -p 2>/dev/null || uptime"),
    ("CPU",                 "lscpu 2>/dev/null | grep -E 'Model name|^CPU\\(s\\)|Thread|Socket' || cat /proc/cpuinfo | head -10"),
    ("Memory",              "free -h 2>/dev/null | head -2"),
    ("Disk",                "df -h / /home 2>/dev/null | head -5"),
    ("Network Interfaces",  "ip -br addr 2>/dev/null || ifconfig 2>/dev/null | head -20"),
    ("Public IP",           "curl -s --max-time 5 ifconfig.me 2>/dev/null || echo 'unavailable'"),
    ("Default Gateway",     "ip route | grep default 2>/dev/null | head -1"),
    ("DNS Resolvers",       "cat /etc/resolv.conf 2>/dev/null | grep nameserver"),
    ("Listening Ports",     "ss -tlnp 2>/dev/null | head -25 || netstat -tlnp 2>/dev/null | head -25"),
    ("Running Services",    "systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -30 || service --status-all 2>/dev/null | grep '+' | head -20"),
    ("Docker Containers",   "docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}' 2>/dev/null | head -20 || echo 'docker not available'"),
    ("Users with Shells",   "grep -v 'nologin\\|false' /etc/passwd | cut -d: -f1,7 2>/dev/null"),
    ("Cron Jobs (root)",    "crontab -l 2>/dev/null || echo 'no crontab'"),
    ("Recent Logins",       "last -n 10 2>/dev/null | head -12"),
    ("Installed Pkg Mgrs",  "which apt yum dnf pacman zypper brew 2>/dev/null"),
    ("Python Version",      "python3 --version 2>/dev/null"),
    ("Key Directories",     "ls -1d /opt /srv /var/www /etc/nginx /etc/apache2 /var/log 2>/dev/null || echo 'none found'"),
    ("Firewall Status",     "ufw status 2>/dev/null || iptables -L -n 2>/dev/null | head -15 || echo 'no firewall detected'"),
]


def generate_system_profile() -> str:
    """Run profiling commands and return Markdown content."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z")
    hostname = subprocess.getoutput("hostname -f 2>/dev/null || hostname").strip()

    lines = [
        f"# System Profile — {hostname}",
        f"",
        f"> Auto-generated by Server Helper on **{now}**",
        f"> Refresh with the `update md` command in chat.",
        f"",
    ]

    for section, cmd in PROFILE_COMMANDS:
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=15,
            )
            output = (result.stdout.strip() or result.stderr.strip() or "(no output)")
        except subprocess.TimeoutExpired:
            output = "(timed out)"
        except Exception as e:
            output = f"(error: {e})"

        lines.append(f"## {section}")
        lines.append("")
        lines.append("```")
        lines.append(output)
        lines.append("```")
        lines.append("")

    return "\n".join(lines)


def ensure_profile() -> str:
    """Create profile on first run; return its contents."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not PROFILE_FILE.exists():
        print(f"\n  {C}{B}First run detected — profiling this system…{RS}")
        content = generate_system_profile()
        PROFILE_FILE.write_text(content)
        os.chmod(str(PROFILE_FILE), 0o600)
        print(f"  {G}✔ Profile saved to {PROFILE_FILE}{RS}\n")
        return content
    return PROFILE_FILE.read_text()


def refresh_profile():
    """Regenerate the profile (called by 'update md')."""
    print(f"  {C}Refreshing system profile…{RS}")
    content = generate_system_profile()
    PROFILE_FILE.write_text(content)
    os.chmod(str(PROFILE_FILE), 0o600)
    print(f"  {G}✔ Profile updated at {PROFILE_FILE}{RS}\n")
    return content


def summarize_profile(content: str) -> str:
    """Extract a compact summary from the profile markdown for the banner."""
    info = {}
    current_section = None
    current_lines = []

    for line in content.split("\n"):
        if line.startswith("## "):
            if current_section and current_lines:
                info[current_section] = "\n".join(current_lines)
            current_section = line[3:].strip()
            current_lines = []
        elif current_section and line.strip() and not line.startswith("```") and not line.startswith(">") and not line.startswith("#"):
            current_lines.append(line.strip())

    if current_section and current_lines:
        info[current_section] = "\n".join(current_lines)

    hostname = info.get("Hostname", "unknown")
    os_info  = info.get("OS / Kernel", "").split("\n")[0].replace("PRETTY_NAME=", "").strip('"') if "OS / Kernel" in info else "unknown"
    cpu      = ""
    if "CPU" in info:
        for l in info["CPU"].split("\n"):
            if "Model name" in l:
                cpu = l.split(":")[-1].strip()
                break
    mem = info.get("Memory", "").split("\n")[-1].strip() if "Memory" in info else ""
    ip_pub   = info.get("Public IP", "").strip()
    ports    = len([l for l in info.get("Listening Ports", "").split("\n") if l.strip() and "State" not in l and "Local" not in l])
    docker   = info.get("Docker Containers", "").strip()
    has_docker = docker and "not available" not in docker and docker != "(no output)"

    parts = []
    if hostname:   parts.append(f"Host: {hostname}")
    if os_info and os_info != "(no output)": parts.append(f"OS: {os_info}")
    if cpu:        parts.append(f"CPU: {cpu}")
    if mem:        parts.append(f"Mem: {mem}")
    if ip_pub and ip_pub != "unavailable": parts.append(f"Public IP: {ip_pub}")
    if ports:      parts.append(f"Listening ports: ~{ports}")
    if has_docker: parts.append("Docker: active")

    return " │ ".join(parts[:4]) + ("\n  " + " │ ".join(parts[4:]) if len(parts) > 4 else "")


# ══════════════════════════════════════════════════════════════════════
#  MODEL SELECTION UI
# ══════════════════════════════════════════════════════════════════════

def choose_model() -> tuple[str, str, str]:
    """
    Interactive model picker. Returns (provider, model_id, model_label).
    """
    print(f"\n  {B}Select a model{RS}")
    print(f"  {DIM}{'─' * 48}{RS}")

    flat = []  # (provider_key, model_dict)
    idx = 1

    for pkey in ("anthropic", "openai"):
        prov = PROVIDERS[pkey]
        color = C if pkey == "anthropic" else G
        print(f"\n  {color}{B}{prov['name']}{RS}")

        for m in prov["models"]:
            has_key = bool(get_key(pkey))
            key_dot = f"{G}●{RS}" if has_key else f"{DIM}○{RS}"
            print(f"    {key_dot} {B}{idx}{RS}  {m['label']:<22} {DIM}{m['desc']}{RS}")
            flat.append((pkey, m))
            idx += 1

    print(f"\n  {DIM}● = API key on file   ○ = key needed{RS}")
    print()

    while True:
        try:
            raw = input(f"  {BLU}{B}Choice [1-{len(flat)}]:{RS} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {DIM}Cancelled.{RS}")
            sys.exit(0)
        if raw.isdigit() and 1 <= int(raw) <= len(flat):
            break
        print(f"  {R}Enter a number between 1 and {len(flat)}.{RS}")

    pkey, model = flat[int(raw) - 1]
    return pkey, model["id"], model["label"]


# ══════════════════════════════════════════════════════════════════════
#  TOOLS (same four, cleaned up)
# ══════════════════════════════════════════════════════════════════════

TOOLS_ANTHROPIC = [
    {
        "name": "bash",
        "description": (
            "Execute a bash command on the server and return stdout+stderr. "
            "Runs as the current user. Use for: listing files, searching, "
            "running scripts, checking services, installing packages, "
            "network diagnostics, etc. Commands time out after 120s."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Bash command to run."}
            },
            "required": ["command"],
        },
    },
    {
        "name": "read_file",
        "description": (
            "Read a file from any path. Large files truncated to 50K chars. "
            "If given a directory, returns a listing."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute path."},
                "max_chars": {"type": "integer", "description": "Max chars (default 50000).", "default": 50000},
            },
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": (
            "Write content to a file, creating it and parent dirs if needed. "
            "Overwrites if it exists."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute path."},
                "content": {"type": "string", "description": "Full content to write."},
                "mode": {"type": "string", "description": "Permissions (default '644').", "default": "644"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "search_files",
        "description": (
            "Search for files by name pattern or search file contents (grep). "
            "Combines find and grep."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "directory": {"type": "string", "description": "Root dir (default '/').", "default": "/"},
                "name_pattern": {"type": "string", "description": "Filename glob (e.g. '*.json')."},
                "content_pattern": {"type": "string", "description": "Text/regex to grep for."},
                "file_types": {"type": "string", "description": "Comma-separated extensions."},
                "max_results": {"type": "integer", "description": "Max results (default 50).", "default": 50},
            },
            "required": ["directory"],
        },
    },
]

# OpenAI uses the same schema but wrapped in {"type":"function","function":{...}}
TOOLS_OPENAI = [
    {
        "type": "function",
        "function": {
            "name": t["name"],
            "description": t["description"],
            "parameters": t["input_schema"],
        },
    }
    for t in TOOLS_ANTHROPIC
]


def execute_tool(name, inp):
    """Execute a tool and return the result string."""

    if name == "bash":
        cmd = inp.get("command", "")
        print(f"  {DIM}$ {cmd[:120]}{RS}")
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=BASH_TIMEOUT, cwd=os.path.expanduser("~"),
            )
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            output = ""
            if stdout:
                output += stdout
            if stderr:
                output += ("\n--- STDERR ---\n" + stderr) if stdout else stderr
            if not output.strip():
                output = f"[Completed — exit code {result.returncode}, no output]"
            if len(output) > MAX_OUTPUT_CHARS:
                output = output[:MAX_OUTPUT_CHARS] + f"\n\n[…TRUNCATED at {MAX_OUTPUT_CHARS} chars — {len(stdout)+len(stderr)} total…]"
            return f"Exit code: {result.returncode}\n{output}"
        except subprocess.TimeoutExpired:
            return f"[TIMEOUT: exceeded {BASH_TIMEOUT}s]"
        except Exception as e:
            return f"[ERROR: {str(e)[:500]}]"

    elif name == "read_file":
        path = inp.get("path", "")
        max_chars = inp.get("max_chars", MAX_OUTPUT_CHARS)
        print(f"  {DIM}📄 {path}{RS}")
        try:
            p = Path(path)
            if not p.exists():
                return f"[Not found: {path}]"
            if p.is_dir():
                entries = sorted(p.iterdir())
                listing = "\n".join(
                    f"  {'[DIR]' if e.is_dir() else '[FILE]'} {e.name}"
                    + (f" ({e.stat().st_size:,}B)" if e.is_file() else "")
                    for e in entries[:200]
                )
                return f"[Directory: {path}]\n{listing}"
            size = p.stat().st_size
            if size > 10 * 1024 * 1024:
                return f"[Too large: {size:,}B — use bash head/tail/grep instead.]"
            content = p.read_text(errors="replace")
            if len(content) > max_chars:
                content = content[:max_chars] + f"\n\n[…TRUNCATED at {max_chars} — file is {size:,}B…]"
            return content
        except PermissionError:
            return f"[Permission denied: {path}]"
        except Exception as e:
            return f"[Error: {str(e)[:300]}]"

    elif name == "write_file":
        path = inp.get("path", "")
        content = inp.get("content", "")
        mode = inp.get("mode", "644")
        print(f"  {DIM}✏️  {path} ({len(content)} chars){RS}")
        try:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
            os.chmod(str(p), int(mode, 8))
            return f"[Written: {path} ({len(content)} chars, mode {mode})]"
        except Exception as e:
            return f"[Error: {str(e)[:300]}]"

    elif name == "search_files":
        directory = inp.get("directory", "/")
        name_pattern = inp.get("name_pattern", "")
        content_pattern = inp.get("content_pattern", "")
        file_types = inp.get("file_types", "")
        max_results = inp.get("max_results", 50)
        print(f"  {DIM}🔍 {directory} name={name_pattern or '*'} content={content_pattern or '*'}{RS}")
        try:
            if content_pattern:
                cmd = "grep -RIn --color=never"
                for ext in (file_types or "").split(","):
                    ext = ext.strip().lstrip(".")
                    if ext:
                        cmd += f' --include="*.{ext}"'
                cmd += f' -i "{content_pattern}" "{directory}" 2>/dev/null | head -n {max_results}'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
                output = result.stdout.strip()
                if not output:
                    return f"[No matches for '{content_pattern}' in {directory}]"
                return f"[{len(output.splitlines())} matches]\n{output}"
            elif name_pattern:
                cmd = f'find "{directory}" -name "{name_pattern}" -type f 2>/dev/null | head -n {max_results}'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
                return result.stdout.strip() or f"[No files matching '{name_pattern}' in {directory}]"
            else:
                cmd = f'find "{directory}" -maxdepth 2 -type f 2>/dev/null | head -n {max_results}'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                return result.stdout.strip() or f"[No files in {directory}]"
        except subprocess.TimeoutExpired:
            return "[Search timed out]"
        except Exception as e:
            return f"[Error: {str(e)[:300]}]"

    return f"[Unknown tool: {name}]"


# ══════════════════════════════════════════════════════════════════════
#  SYSTEM PROMPT BUILDER
# ══════════════════════════════════════════════════════════════════════

def build_system_prompt(profile_content: str, model_label: str) -> str:
    hostname = subprocess.getoutput("hostname -f 2>/dev/null || hostname").strip()
    user = os.environ.get("USER", "unknown")
    return f"""You are **Server Helper**, an agentic CLI assistant running directly on
the machine **{hostname}** as user **{user}**. The operator launched you
from the terminal to help manage, investigate, code on, and automate tasks
on this box. You are using model **{model_label}**.

Your job is to act — not advise. When the operator asks you to find, fix,
build, or investigate something, use your tools to actually do it. Show
your work, cite file paths and line numbers, and iterate if your first
attempt doesn't succeed.

═══ ENVIRONMENT ═══
  OS:       {os.uname().sysname} {os.uname().release}
  Host:     {hostname}
  User:     {user}
  Home:     {os.path.expanduser('~')}
  CWD:      {os.getcwd()}
  Time:     {datetime.now().strftime('%Y-%m-%d %H:%M %Z')}
  Profile:  {PROFILE_FILE}

═══ SYSTEM PROFILE (auto-collected) ═══
{profile_content[:6000]}

═══ TOOLS ═══
  1. bash        — Run any shell command (full system access).
  2. read_file   — Read any file or list a directory.
  3. write_file  — Create/overwrite files anywhere.
  4. search_files — Find files by name or grep content.

═══ RULES ═══
  - USE YOUR TOOLS. Don't guess, don't say "you could try". Actually do it.
  - Chain tool calls. If the first search misses, try different terms.
  - You can use up to {DEFAULT_MAX_ROUNDS} tool rounds per turn.
  - CONTEXT MANAGEMENT: prefer bash with head/tail/grep/jq over reading
    full files. Never read more than you need.
  - Before searching /, check ~/ and common data dirs first.
  - Never delete data without explicit confirmation.
  - Be direct. The operator is technical. No fluff.
  - When you encounter errors, troubleshoot and fix them.
  - If the operator says "update md", regenerate the system profile by
    running the same profiling commands and writing to {PROFILE_FILE}.
"""


# ══════════════════════════════════════════════════════════════════════
#  API CALL — ANTHROPIC
# ══════════════════════════════════════════════════════════════════════

def call_anthropic(messages, api_key, model_id, system_prompt, max_rounds):
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    total_in = total_out = tool_calls = 0

    for rnd in range(1, max_rounds + 1):
        # Trim context if needed
        _trim_context(messages)

        payload = {
            "model": model_id,
            "max_tokens": MAX_TOKENS,
            "system": system_prompt,
            "messages": messages,
            "tools": TOOLS_ANTHROPIC,
        }
        try:
            resp = requests.post(PROVIDERS["anthropic"]["api_url"], headers=headers, json=payload, timeout=180)
            resp.raise_for_status()
            result = resp.json()
        except requests.exceptions.RequestException as e:
            print(f"  {R}✘ API error: {e}{RS}")
            return f"[API error: {str(e)[:200]}]", total_in, total_out, tool_calls

        usage = result.get("usage", {})
        total_in  += usage.get("input_tokens", 0)
        total_out += usage.get("output_tokens", 0)

        stop = result.get("stop_reason", "")
        blocks = result.get("content", [])

        # Show mid-chain thinking
        for b in blocks:
            if b.get("type") == "text" and b.get("text", "").strip() and stop == "tool_use":
                print(f"  {DIM}{b['text'][:200]}{RS}")

        if stop == "tool_use":
            messages.append({"role": "assistant", "content": blocks})
            tool_results = []
            for b in blocks:
                if b.get("type") == "tool_use":
                    tool_calls += 1
                    print(f"  {C}⚙{RS}  {Y}{b['name']}{RS} [{rnd}/{max_rounds}]")
                    out = execute_tool(b["name"], b["input"])
                    tool_results.append({"type": "tool_result", "tool_use_id": b["id"], "content": out})
            messages.append({"role": "user", "content": tool_results})
            continue

        text = "\n".join(b.get("text", "") for b in blocks if b.get("type") == "text").strip()
        return text, total_in, total_out, tool_calls

    return "[Max tool rounds reached]", total_in, total_out, tool_calls


# ══════════════════════════════════════════════════════════════════════
#  API CALL — OPENAI
# ══════════════════════════════════════════════════════════════════════

def call_openai(messages_internal, api_key, model_id, system_prompt, max_rounds):
    """
    Translate internal (Anthropic-shaped) messages to OpenAI format,
    call the API, execute tools, and loop.
    """
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    total_in = total_out = tool_calls = 0

    # Build OpenAI messages from scratch each round
    # Keep a local OpenAI-format conversation
    oai_msgs = [{"role": "system", "content": system_prompt}]

    # Convert existing history (plain text user/assistant messages only for seeding)
    for m in messages_internal:
        role = m.get("role", "")
        content = m.get("content", "")
        if isinstance(content, str) and role in ("user", "assistant"):
            oai_msgs.append({"role": role, "content": content})

    for rnd in range(1, max_rounds + 1):
        payload = {
            "model": model_id,
            "max_completion_tokens": MAX_TOKENS,
            "messages": oai_msgs,
            "tools": TOOLS_OPENAI,
        }
        try:
            resp = requests.post(PROVIDERS["openai"]["api_url"], headers=headers, json=payload, timeout=180)
            resp.raise_for_status()
            result = resp.json()
        except requests.exceptions.RequestException as e:
            print(f"  {R}✘ API error: {e}{RS}")
            return f"[API error: {str(e)[:200]}]", total_in, total_out, tool_calls

        usage = result.get("usage", {})
        total_in  += usage.get("prompt_tokens", 0)
        total_out += usage.get("completion_tokens", 0)

        choice = result["choices"][0]
        msg = choice["message"]
        finish = choice.get("finish_reason", "")

        if finish == "tool_calls" or msg.get("tool_calls"):
            # Append assistant message with tool_calls
            oai_msgs.append(msg)

            for tc in msg["tool_calls"]:
                fn = tc["function"]
                tool_name = fn["name"]
                try:
                    tool_input = json.loads(fn["arguments"])
                except json.JSONDecodeError:
                    tool_input = {}
                tool_calls += 1
                print(f"  {C}⚙{RS}  {Y}{tool_name}{RS} [{rnd}/{max_rounds}]")
                out = execute_tool(tool_name, tool_input)
                oai_msgs.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": out,
                })
            continue

        text = msg.get("content", "") or ""
        # Mirror back to internal history
        messages_internal.append({"role": "assistant", "content": text})
        return text.strip(), total_in, total_out, tool_calls

    return "[Max tool rounds reached]", total_in, total_out, tool_calls


# ══════════════════════════════════════════════════════════════════════
#  CONTEXT TRIMMING
# ══════════════════════════════════════════════════════════════════════

def _trim_context(messages):
    ctx = sum(len(json.dumps(m, default=str)) for m in messages)
    if ctx <= MAX_CONTEXT_CHARS:
        return
    trimmed = 0
    for m in messages:
        if isinstance(m.get("content"), list):
            for b in m["content"]:
                if b.get("type") == "tool_result" and isinstance(b.get("content"), str):
                    if len(b["content"]) > 2000:
                        old = len(b["content"])
                        b["content"] = b["content"][:1500] + f"\n[…trimmed from {old} chars…]"
                        trimmed += old - 1500
    if trimmed:
        print(f"  {DIM}[Context trimmed: ~{trimmed:,} chars freed]{RS}")


def prune_conversation(conversation):
    """Drop old tool exchanges to keep context manageable."""
    ctx = sum(len(json.dumps(m, default=str)) for m in conversation)
    if ctx <= MAX_CONTEXT_CHARS and len(conversation) <= 40:
        return conversation

    pruned = []
    i = 0
    while i < len(conversation):
        msg = conversation[i]
        if i >= len(conversation) - 6:
            pruned.append(msg)
            i += 1
            continue
        content = msg.get("content", "")
        if isinstance(content, str):
            if len(content) > 1000:
                msg = dict(msg)
                msg["content"] = content[:800] + "\n[…truncated…]"
            pruned.append(msg)
        elif isinstance(content, list):
            has_tool = any(b.get("type") in ("tool_use", "tool_result") for b in content if isinstance(b, dict))
            if has_tool and i < len(conversation) - 10:
                if i + 1 < len(conversation):
                    nc = conversation[i + 1].get("content", "")
                    if isinstance(nc, list) and any(b.get("type") == "tool_result" for b in nc if isinstance(b, dict)):
                        i += 2
                        continue
                i += 1
                continue
            else:
                pruned.append(msg)
        else:
            pruned.append(msg)
        i += 1

    if len(pruned) < len(conversation):
        print(f"  {DIM}[Pruned {len(conversation) - len(pruned)} old tool exchanges]{RS}\n")
    return pruned


# ══════════════════════════════════════════════════════════════════════
#  UNIFIED DISPATCHER
# ══════════════════════════════════════════════════════════════════════

def call_model(provider, model_id, model_label, api_key, system_prompt,
               conversation, max_rounds):
    """Route to the right provider's API loop."""
    if provider == "anthropic":
        return call_anthropic(conversation, api_key, model_id, system_prompt, max_rounds)
    else:
        return call_openai(conversation, api_key, model_id, system_prompt, max_rounds)


# ══════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Server Helper — Multi-Provider Agentic CLI")
    parser.add_argument("--ask", help="Single question mode — ask and exit")
    parser.add_argument("--max-rounds", type=int, default=DEFAULT_MAX_ROUNDS,
                        help=f"Max tool iterations per turn (default {DEFAULT_MAX_ROUNDS})")
    args = parser.parse_args()
    max_rounds = args.max_rounds

    # ── Startup banner ───────────────────────────────────────────────
    print(f"""
  {B}{TL}{'─'*54}{TR}{RS}
  {B}{V}{RS}  {WHT}{B}SERVER HELPER{RS}  {DIM}Multi-Provider Agentic CLI{RS}      {B}{V}{RS}
  {B}{BL}{'─'*54}{BR}{RS}""")

    # ── System profile ───────────────────────────────────────────────
    profile_content = ensure_profile()
    summary = summarize_profile(profile_content)
    print(f"  {DIM}{summary}{RS}\n")

    # ── Model selection ──────────────────────────────────────────────
    provider, model_id, model_label = choose_model()

    # ── API key ──────────────────────────────────────────────────────
    api_key = get_key(provider)
    if not api_key:
        api_key = prompt_and_save_key(provider)

    # ── Connectivity test ────────────────────────────────────────────
    if not test_connectivity(provider, model_id, api_key):
        print(f"\n  {R}Could not connect. Check your API key and network.{RS}")
        yn = input(f"  {Y}Re-enter API key? (y/n):{RS} ").strip().lower()
        if yn in ("y", "yes"):
            api_key = prompt_and_save_key(provider)
            if not test_connectivity(provider, model_id, api_key):
                print(f"  {R}Still failing — exiting.{RS}\n")
                sys.exit(1)
        else:
            sys.exit(1)

    # ── Build system prompt ──────────────────────────────────────────
    system_prompt = build_system_prompt(profile_content, model_label)

    # ── Readline ─────────────────────────────────────────────────────
    CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        readline.read_history_file(str(HISTORY_FILE))
    except FileNotFoundError:
        pass
    readline.set_history_length(500)

    masked_key = api_key[:6] + "•" * 10 + api_key[-4:]
    print(f"""
  {B}{'─'*54}{RS}
  {B}  Model:  {model_label}{RS}  {DIM}({model_id}){RS}
  {B}  Provider: {PROVIDERS[provider]['name']}{RS}
  {B}  Key:    {masked_key}{RS}
  {B}  Rounds: {max_rounds} max per turn{RS}
  {B}{'─'*54}{RS}

  {DIM}Commands: /clear  /cost  /model  /key  /help  /quit{RS}
  {DIM}Say "update md" in chat to refresh the system profile.{RS}
""")

    conversation = []
    session_in = session_out = 0

    # ── Single question mode ─────────────────────────────────────────
    if args.ask:
        conversation.append({"role": "user", "content": args.ask})
        print(f"  {BLU}{B}You:{RS} {args.ask}\n")
        resp, it, ot, tc = call_model(provider, model_id, model_label, api_key,
                                       system_prompt, conversation, max_rounds)
        conversation.append({"role": "assistant", "content": resp})
        print(f"\n  {MAG}{B}Helper:{RS}\n")
        print(resp)
        print(f"\n  {DIM}[{it:,} in / {ot:,} out / {tc} tool calls]{RS}\n")
        return

    # ── Interactive loop ─────────────────────────────────────────────
    while True:
        try:
            user_input = input(f"  {BLU}{B}You:{RS} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {DIM}Goodbye.{RS}\n")
            break

        if not user_input:
            continue

        try:
            readline.write_history_file(str(HISTORY_FILE))
        except Exception:
            pass

        low = user_input.lower().strip()

        # ── Slash commands ───────────────────────────────────────────
        if low in ("/quit", "/exit", "/q"):
            print(f"  {DIM}Goodbye.{RS}\n")
            break

        elif low == "/clear":
            conversation = []
            print(f"  {G}✔ History cleared{RS}\n")
            continue

        elif low == "/cost":
            print(f"  {DIM}Session tokens: {session_in:,} in / {session_out:,} out{RS}")
            print(f"  {DIM}Messages in history: {len(conversation)}{RS}\n")
            continue

        elif low == "/model":
            provider, model_id, model_label = choose_model()
            api_key = get_key(provider)
            if not api_key:
                api_key = prompt_and_save_key(provider)
            if not test_connectivity(provider, model_id, api_key):
                print(f"  {R}Connection failed — staying on previous model.{RS}")
                continue
            system_prompt = build_system_prompt(profile_content, model_label)
            conversation = []
            print(f"  {G}✔ Switched to {model_label}. History cleared.{RS}\n")
            continue

        elif low == "/key":
            api_key = prompt_and_save_key(provider)
            test_connectivity(provider, model_id, api_key)
            continue

        elif low == "/help":
            print(f"""
  {B}Commands:{RS}
    /clear   — Reset conversation history
    /cost    — Show token usage
    /model   — Switch model or provider mid-session
    /key     — Update API key for current provider
    /help    — This help
    /quit    — Exit

  {B}Special:{RS}
    "update md" — Refresh system profile (re-scans the box)

  {B}Tips:{RS}
    Be specific: "find all JSON files in /var/log/ containing 'error'"
    Build: "write a script that parses all .conf files into a summary"
    Investigate: "show all services and open ports on this box"
""")
            continue

        # ── "update md" ──────────────────────────────────────────────
        if low in ("update md", "update profile", "refresh md", "refresh profile"):
            profile_content = refresh_profile()
            system_prompt = build_system_prompt(profile_content, model_label)
            summary = summarize_profile(profile_content)
            print(f"  {DIM}{summary}{RS}\n")
            continue

        # ── Normal message ───────────────────────────────────────────
        conversation.append({"role": "user", "content": user_input})
        print()

        resp, it, ot, tc = call_model(provider, model_id, model_label, api_key,
                                       system_prompt, conversation, max_rounds)
        session_in += it
        session_out += ot

        if resp.startswith("[API error:") and "400" in resp:
            print(f"\n  {R}Context corrupted — clearing history.{RS}")
            conversation = []
            print(f"  {G}✔ Cleared. Please re-ask your question.{RS}\n")
            continue

        conversation.append({"role": "assistant", "content": resp})

        print(f"\n  {MAG}{B}Helper:{RS}\n")
        for line in resp.split("\n"):
            print(f"  {line}")
        print(f"\n  {DIM}[{it:,} in / {ot:,} out / {tc} tool calls]{RS}\n")

        conversation = prune_conversation(conversation)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda s, f: (print(f"\n  {DIM}Interrupted. /quit to exit.{RS}\n"), None))
    main()
