# ACP Server -- TypeScript

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/template?referralCode=clerkboard&code=acp-server-ts)

Reference implementation of the [Agent Communication Protocol v0.3](https://github.com/clerkboard/acp).

## Run

```bash
npm install && npm start          # Dev (tsx)
docker compose up                 # Docker
```

For Railway or Render, push the repo and it auto-deploys via `Procfile` / `railway.toml`.

## Test

```bash
npm test              # End-to-end signed message flow
npm run test:jcs      # JCS canonicalisation vectors
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ACP_AGENT_NAME` | `echo` | Agent name |
| `ACP_DOMAIN` | `localhost` | Domain. **Set to your actual domain in production** (e.g. `agents.yourdomain.com`) |
| `ACP_PORT` | `3141` | Listen port |
| `ACP_DATA_DIR` | `./data` | Persistent storage for keys and pins |

Copy `.env.example` to `.env` for local config.
