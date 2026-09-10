#!/bin/sh
set -e

# ── ywsj-kms entrypoint ──
# Starts vlmcsd, log watcher thread (inside gunicorn worker), and gunicorn.
# Must run as root initially to fix /data permissions, then drops to appuser.

DATA_DIR="/data"
APPUSER="appuser"
APPUID=1000

# Ensure data directory exists and is owned by appuser
mkdir -p "$DATA_DIR"
chown -R "$APPUID:$APPUID" "$DATA_DIR" 2>/dev/null || true

# Initialize database (creates tables + admin user if needed)
python3 -c "from app import init_db; init_db()"

# Start vlmcsd as appuser (it needs to bind port 1688 — privileged on host network)
# In container with bridge network, port 1688 binding doesn't need root.
su-exec "$APPUSER" vlmcsd -v -l "$DATA_DIR/kms.log" -t 30 -d 2>/dev/null &
echo "vlmcsd started, logging to $DATA_DIR/kms.log"

# Start gunicorn (log watcher thread starts inside the app on import)
exec su-exec "$APPUSER" gunicorn \
    --bind "0.0.0.0:${WEB_PORT:-8080}" \
    --workers 1 \
    --threads 4 \
    --timeout 30 \
    --access-logfile - \
    --error-logfile - \
    app:app
