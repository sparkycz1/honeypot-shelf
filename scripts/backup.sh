#!/usr/bin/env bash
# Back up everything a running Honeypot Shelf instance needs to be restored from
# scratch: the Postgres database, and `.env` (holds ENCRYPTION_KEY, without
# which every stored honeypot password/private key and other encrypted
# secret is unrecoverable ciphertext, plus SECRET_KEY, POSTGRES_PASSWORD,
# REDIS_PASSWORD, INFORM_TOKEN). Unlike debcontrol, Honeypot Shelf keeps no
# shared app-level SSH identity volume to back up separately — every
# honeypot's own credential lives in the database, encrypted with
# ENCRYPTION_KEY (see app.core.security).
#
# Run this from the git checkout on the server, as whichever user normally
# runs `docker compose` here:
#
#   ./scripts/backup.sh
#
# What it does, in order:
#   1. `pg_dump` in the bundled database (`db`, or `timescaledb` with that
#      profile) — a live, consistent snapshot via Postgres's own MVCC; the
#      stack does NOT need to be stopped for this. With your own database
#      (no database profile) this step is skipped.
#   2. Copies `.env` as-is.
#   3. Writes everything into one timestamped directory under
#      `BACKUP_DIR` (default ./backups), `chmod 600`'d — this holds
#      unencrypted secrets and honeypot credentials once decrypted with
#      ENCRYPTION_KEY, treat it exactly like a `.env` file.
#   4. Prunes backup directories older than `BACKUP_RETENTION_DAYS`
#      (default 14) so this is safe to run unattended from cron forever
#      without slowly filling the disk — see wiki/Installation.md
#      ("Backups") for a ready-to-use crontab line.
#
# Restoring: ./scripts/restore.sh <path to one timestamped backup dir>

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ ! -f docker-compose.yml ]; then
  echo "error: docker-compose.yml not found here — run this from the Honeypot Shelf checkout." >&2
  exit 1
fi

if [ ! -f .env ]; then
  echo "error: .env not found here — nothing to back up (is this a real deployment?)." >&2
  exit 1
fi

# shellcheck disable=SC1091
source .env

backup_dir="${BACKUP_DIR:-./backups}"
retention_days="${BACKUP_RETENTION_DAYS:-14}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
dest="${backup_dir}/${timestamp}"

mkdir -p "$dest"

# The bundled database is `db` (profile postgres) or `timescaledb`; with
# neither, the database is your own and is backed up with its own tools.
# shellcheck source=scripts/compose_profiles.sh
. scripts/compose_profiles.sh
db_service="$(database_service)"
if [ -z "$db_service" ]; then
  echo "==> No bundled database (COMPOSE_PROFILES='$(current_profiles)'): back up your own"
  echo "    database with its own tools; this saves .env only."
else
  if ! docker compose ps "$db_service" --format '{{.State}}' 2>/dev/null | grep -q .; then
    echo "error: the '$db_service' service isn't running (docker compose ps). Start the stack first." >&2
    exit 1
  fi
  echo "==> Dumping database (${POSTGRES_DB:-honeypotshelf}, $db_service)..."
  docker compose exec -T "$db_service" pg_dump -U "${POSTGRES_USER}" "${POSTGRES_DB}" \
    | gzip > "${dest}/db.sql.gz"
  # restore.sh needs to know: a TimescaleDB dump only restores into TimescaleDB.
  echo "$db_service" > "${dest}/db-kind"
fi

echo "==> Copying .env..."
cp .env "${dest}/env.backup"

chmod -R go-rwx "$dest"

echo "==> Pruning backups older than ${retention_days} day(s) in ${backup_dir}..."
find "$backup_dir" -mindepth 1 -maxdepth 1 -type d -mtime "+${retention_days}" -print -exec rm -rf {} \;

echo
echo "Done: ${dest}"
if [ -f "${dest}/db.sql.gz" ]; then
  echo "  db.sql.gz  — $(du -h "${dest}/db.sql.gz" | cut -f1) ($(cat "${dest}/db-kind"))"
fi
echo "  env.backup — $(du -h "${dest}/env.backup" | cut -f1)"
echo
echo "This directory contains secrets in the clear (env.backup, and every"
echo "value the database dump can decrypt once combined with it) — copy it"
echo "somewhere access-controlled (off this host, ideally) rather than"
echo "leaving it only in ./backups."
