# ACP Server -- TypeScript

Reference implementation of the [Agent Communication Protocol v0.3](https://github.com/clerkboard/acp).

## Quick Start

```bash
npm install
npm start        # Starts echo agent on port 3141
```

## Test

```bash
npm test         # Sends signed messages and verifies responses
```

## Config

Copy `.env.example` to `.env` and edit:

- `ACP_AGENT_NAME` -- Agent name (default: echo)
- `ACP_DOMAIN` -- Domain (default: localhost)
- `ACP_PORT` -- Port (default: 3141)
