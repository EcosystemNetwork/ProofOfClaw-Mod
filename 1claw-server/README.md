# 1clawAI API Server

Local API server for credential storage, retrieval, and monetization.

## Quick Start

```bash
cd 1claw-server
npm install
npm start
```

Server runs on `http://localhost:3456`

## Endpoints

### Storage
- `POST /v1/store` - Store data with key
- `POST /v1/retrieve` - Retrieve data by key  
- `DELETE /v1/delete/:key` - Delete data

### License
- `POST /v1/license/verify` - Verify license key
- `POST /v1/license/validate` - Validate package license

### Payment
- `POST /v1/payment/checkout` - Create checkout session

### Agent Tasks
- `POST /v1/agents/tasks` - Store agent tasks
- `GET /v1/agents/:agentId/tasks` - Retrieve agent tasks

### Health
- `GET /health` - Server status

## Configuration

Set in root `.env`:
```
ONECLAW_PORT=3456
ONECLAW_API_KEY=your-api-key
```

## Data Storage

Files stored in `1claw-server/data/` as JSON. Automatic fallback to localStorage in browser if server unavailable.
