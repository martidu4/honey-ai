# Contributing to HoneyAI

Thanks for your interest in contributing! HoneyAI is an open-source project and we welcome contributions from the community.

## Getting Started

1. Fork the repo
2. Clone your fork: `git clone https://github.com/YOUR_USER/honey-ai.git`
3. Install dependencies: `pnpm install` (npm/yarn are blocked — see [why](README.md#requirements))
4. Copy config: `cp config.example.yaml config.yaml`
5. Run the setup wizard: `pnpm run setup`
6. Start the server: `pnpm start`

## Development

```bash
pnpm run dev    # Start with --watch (auto-restart on changes)
pnpm test       # Run the test suite (requires Ollama running)
```

## What Can I Contribute?

### 🔌 New Protocol Handlers
Add new protocols in `protocols/`. Follow the pattern in `tcp.js` — each protocol needs:
- A listener function
- AI system prompt for the protocol persona
- Static responses for common commands (to avoid LLM load)
- Tests in `test-qa.js`

Ideas: SIP/VoIP, Modbus/ICS, SNMP, DNS, LDAP, SMB, MQTT.

### 🧠 Better AI Prompts
Improve the system prompts in `ai/engine.js`. The goal is to make responses as realistic as possible while never leaking that it's a honeypot.

### 📊 Web Dashboard
Build a web UI for the management API (`:9999`). The API already exposes `/health`, `/stats`, and `/events`.

### 🌍 Identity Leak Patterns
Add patterns to detect identity leaks in more languages. Currently supported: English, Spanish, Chinese, Russian, Korean, Arabic, Portuguese, French.

### 🧪 Tests
Add test cases to `test-qa.js`. Each test should verify that a specific attack vector returns a convincing response.

## Code Style

- **No TypeScript** — this is a deliberately simple Node.js project
- Use `const` over `let` where possible
- Error handling: always catch, never crash the process
- Security: sanitize all attacker input before logging or processing
- Comments: explain *why*, not *what*

## Pull Request Process

1. Create a feature branch: `git checkout -b feat/my-feature`
2. Make your changes
3. Run tests: `pnpm test`
4. Commit with a clear message: `feat(protocol): add SNMP honeypot handler`
5. Push and open a PR against `main`

## Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(scope): add new feature
fix(scope): fix a bug
docs: update documentation
test: add or update tests
chore: maintenance tasks
perf: performance improvements
refactor: code refactoring
```

## Security

If you discover a security vulnerability, **please do NOT open a public issue**. Instead, email the maintainer or open a private security advisory on GitHub.

## License

By contributing, you agree that your contributions will be licensed under the [AGPL-3.0](LICENSE) license.
