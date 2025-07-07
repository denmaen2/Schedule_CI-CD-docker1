#!/bin/bash
set -e

# Відновлюємо дамп у базу database
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname="$POSTGRES_DB" -f /database.dump
