#!/bin/sh
set -e

echo "Waiting for the database..."
python - <<'PYEOF'
import sys
import time

from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError

from app.core.config import settings

for attempt in range(30):
    try:
        create_engine(settings.database_url).connect().close()
        break
    except OperationalError:
        time.sleep(1)
else:
    print("Database never became available.", file=sys.stderr)
    sys.exit(1)
PYEOF

echo "Running migrations..."
alembic upgrade head

if [ "$SEED_DB" = "true" ]; then
    echo "Seeding demo data..."
    python seed.py
fi

exec "$@"
