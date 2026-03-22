#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

echo "Starting Autobahn fuzzingserver..."
docker compose -f docker-compose.autobahn.yml up -d

echo "Waiting for server to be ready..."
until nc -z localhost 9001 2>/dev/null; do
    sleep 0.5
done
echo "Server ready."

echo "Running Autobahn test suite..."
rebar3 ct --suite test/autobahn_SUITE || true

echo "Stopping Autobahn fuzzingserver..."
docker compose -f docker-compose.autobahn.yml down

echo ""
echo "Results: test/autobahn/reports/index.html"
