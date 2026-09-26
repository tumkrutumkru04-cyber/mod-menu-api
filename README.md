# Railway Key API

A small Flask API for expiring access keys with one-device binding. It uses SQLite and stores only a SHA-256 hash of each device ID.

## Deploy on Railway

1. Create a new Railway project from this folder or GitHub repository.
2. Add a **volume mounted at `/data`** so SQLite survives redeploys.
3. Add environment variables:
   - `DATABASE_PATH=/data/keys.db`
   - `DEFAULT_CLAIM_HOURS=24`
   - `MAX_HOURS=8760`
4. Railway detects the Dockerfile and starts the service automatically.

Generate tokens locally:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

## Endpoints

### Health

```http
GET /health
```

### Automatic 24-hour, one-device key

Use this from your own client or service.

```bash
curl -X POST https://YOUR-APP.up.railway.app/api/v1/keys/claim \
  -H 'Content-Type: application/json' \
  -d '{"hours":24,"max_devices":1,"prefix":"HEX-CHATS"}'
```

Example response:

```json
{
  "ok": true,
  "key": "HEX-CHATS-6A8F9010",
  "validity": "24 Hours",
  "expires_at": "2026-09-26 14:02:26 UTC",
  "max_devices": 1,
  "used_devices": 0,
  "revoked": false
}
```

### Create a custom key

Use either hours or days. This endpoint is intentionally open Protect it with Railway access controls or add authentication before exposing it publicly.

```bash
curl -X POST https://YOUR-APP.up.railway.app/api/v1/keys/create \
  -H 'Content-Type: application/json' \
  -d '{"days":7,"max_devices":3,"prefix":"VIP"}'
```

```bash
curl -X POST https://YOUR-APP.up.railway.app/api/v1/keys/create \
  -H 'Content-Type: application/json' \
  -d '{"hours":10,"max_devices":1,"prefix":"HEX-CHATS"}'
```

### Validate and bind a device

Your C++/Android client sends its own stable device identifier. The API stores only its hash.

```bash
curl -X POST https://YOUR-APP.up.railway.app/api/v1/keys/validate \
  -H 'Content-Type: application/json' \
  -d '{"key":"HEX-CHATS-6A8F9010","device_id":"your-client-device-id"}'
```

The first device is bound automatically. A different device receives `Device limit reached` when `max_devices` is 1.

### Inspect a key

```bash
curl https://YOUR-APP.up.railway.app/api/v1/keys/HEX-CHATS-6A8F9010
```

### Revoke a key (admin)

```bash
curl -X POST https://YOUR-APP.up.railway.app/api/v1/keys/revoke \
  -H 'Content-Type: application/json' \
  -d '{"key":"HEX-CHATS-6A8F9010"}'
```

## Important notes

- All endpoints are open in this simple version. Protect the Railway service with your own access control before exposing it publicly.
- The API does not include the external server or hardcoded keys from the linked `Login.h`.
- For production, use Railway HTTPS and a persistent volume at `/data`.
- SQLite with one Gunicorn worker is appropriate for a small key service. Move to Postgres if you need multiple replicas or high traffic.
