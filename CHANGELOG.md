# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-05-16

### Added
- Multi-provider model selection at startup (Anthropic and OpenAI)
- Anthropic models: Claude Sonnet 4.6, Claude Opus 4.7, Claude Haiku 4.5
- OpenAI models: GPT-5.5, GPT-5.4, GPT-5.4 Mini, GPT-4.1, GPT-4.1 Mini
- Encrypted API key storage using Fernet with PBKDF2-derived machine key
- API connectivity test on startup before entering chat
- Automatic system profiling on first run (writes `~/.server_helper/system_profile.md`)
- System profile summary in startup banner on subsequent runs
- `update md` command to refresh the system profile mid-session
- `/model` command to switch models or providers without restarting
- Four agentic tools: `bash`, `read_file`, `write_file`, `search_files`
- Agentic tool loop with up to 25 rounds per turn
- Automatic context trimming and conversation pruning
- Single-question mode with `--ask`
- Readline history persistence
