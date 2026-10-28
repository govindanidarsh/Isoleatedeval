#!/usr/bin/env bash
cd "$(dirname "$0")"

echo "=========================================================="
echo " Starting ISOLATEDEVAL..."
echo "=========================================================="

# Wait a second then open browser automatically
(sleep 1 && open "http://localhost:8000") &

# Start backend server
node backend/server.js
