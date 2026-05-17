# Security

## Important: This tool runs shell commands

Server Helper gives an AI model direct access to run shell commands as whatever user launches the script. This is the entire point of the tool, but it means:

- **Do not run this on production systems** without understanding the risk
- **Running as root** gives the model unrestricted system access
- The model has a soft guardrail (system prompt) asking it to confirm before destructive operations, but this is not enforced programmatically
- Review what the model is doing — tool calls are printed to the terminal in real time

## API Key Storage

- API keys are encrypted at rest using `cryptography.fernet.Fernet`
- The encryption key is derived via PBKDF2-HMAC-SHA256 (480,000 iterations) from `/etc/machine-id` and a random per-install salt
- Key files are stored in `~/.server_helper/` with `0600` permissions
- Keys are tied to the machine — copying `keys.enc` to another box won't decrypt it

## Reporting Vulnerabilities

If you find a security issue, please open a GitHub issue or reach out directly. This is a single-file CLI tool, not a hosted service, so the threat model is mostly about local key storage and safe defaults.

## What this tool does NOT do

- It does not send data anywhere except the API provider you selected (Anthropic or OpenAI)
- It does not phone home, collect telemetry, or log to external services
- It does not store conversation history to disk (only readline input history)
