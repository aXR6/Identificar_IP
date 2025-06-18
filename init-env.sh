#!/usr/bin/env bash
# Simple helper to load environment variables from .env
if [ -f "$(dirname "$0")/.env" ]; then
    set -a
    . "$(dirname "$0")/.env"
    set +a
else
    echo ".env não encontrado" >&2
fi
