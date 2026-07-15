#!/usr/bin/env bash
#
# Project Temple Guard — back up the database.
#   ./backup.sh                 # dump Postgres to ./backups/templeguard-<ts>.sql.gz
#   ./backup.sh restore FILE    # restore a dump into the running Postgres
#
# Sync the backups/ folder to the cloud however you like, e.g.:
#   rclone copy backups remote:templeguard-backups
#   aws s3 sync backups s3://my-bucket/templeguard-backups
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p backups

PG_SVC=postgres
DB=templeguard
USER=temple

if [ "${1:-}" = "restore" ]; then
  FILE="${2:?usage: ./backup.sh restore <file.sql.gz>}"
  echo "⛨  Restoring $FILE into $DB…"
  gunzip -c "$FILE" | docker compose exec -T "$PG_SVC" psql -U "$USER" -d "$DB"
  echo "✓ restored"
  exit 0
fi

TS="$(date +%Y%m%d-%H%M%S)"
OUT="backups/templeguard-${TS}.sql.gz"
echo "⛨  Dumping $DB → $OUT"
docker compose exec -T "$PG_SVC" pg_dump -U "$USER" -d "$DB" | gzip > "$OUT"
echo "✓ $(du -h "$OUT" | cut -f1)  $OUT"
echo "  Sync ./backups to the cloud (rclone / aws s3 sync) when ready."
