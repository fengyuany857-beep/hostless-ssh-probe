# Hostless SSH outbound probe

Environment variables:
- `TARGET_HOST`: fixed target VPS hostname/IP
- `TARGET_PORT`: defaults to `22`
- `PROBE_TOKEN`: random secret used to authorize `/probe`

Hostless provides `PORT` automatically.

Endpoints:
- `GET /health` -> always 200 while app is alive
- `GET /probe` with `Authorization: Bearer <PROBE_TOKEN>` -> tests only TARGET_HOST:TARGET_PORT
