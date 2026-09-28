#!/usr/bin/env bash
# The push schema against a real Postgres: apply the tenant migrations to a fresh database, then
# drive tests/schema.sql through every role. Needs docker (STACK_ENGINE=podman for podman).
#
#   bash tests/schema.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
engine="${STACK_ENGINE:-docker}"
name="snout-push-schema-$$"

"$engine" run -d --rm --name "$name" -e POSTGRES_PASSWORD=test postgres:17-alpine >/dev/null
trap '"$engine" rm -f "$name" >/dev/null 2>&1 || true' EXIT
for _ in $(seq 1 60); do
	"$engine" exec "$name" pg_isready -U postgres -q && break
	sleep 0.5
done
# pg_isready answers during the entrypoint's own restart; wait for the real server.
until "$engine" exec "$name" psql -U postgres -tAc 'select 1' >/dev/null 2>&1; do sleep 0.5; done

psql() { "$engine" exec -i "$name" psql -U postgres -v ON_ERROR_STOP=1 -q "$@"; }

psql -c 'CREATE SCHEMA push'
for file in "$here"/../migrations/tenant/*.sql; do
	{ echo "SET push.install_roles = 'true';"; cat "$file"; } | psql
done
psql <"$here/schema.sql"
