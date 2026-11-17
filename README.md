# Wakeboard

Power controller for homelab machines: wake, shut down, reboot and inspect devices
from a web UI, a REST API (`/api/v1`) and an MCP server (`/mcp`).

Vendored front-end: htmx 2.0.4 (`src/wakeboard/web/static/htmx.min.js`,
sha256 `e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447`);
see `src/wakeboard/web/static/VENDORED.txt`. The UI loads nothing from external hosts.
