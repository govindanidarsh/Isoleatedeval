#!/usr/bin/env bash
set -e

PORT="${PORT:-8000}"
HOST="${HOST:-0.0.0.0}"

echo "=========================================================="
echo " Starting ISOLATEDEVAL Secure Backend Server"
echo "=========================================================="

if ! command -v node >/dev/null 2>&1; then
  echo "Error: Node.js is required but not installed." >&2
  exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 20 ]; then
  echo "Warning: Node.js 22+ recommended (found $(node -v))."
fi

cd "$(dirname "$0")"

# Start backend server
node backend/server.js
