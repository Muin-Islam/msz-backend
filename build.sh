#!/bin/bash
set -e # Exit on error

# Install dependencies
npm install

# Build TypeScript
npx tsc --project tsconfig.json

# Verify build output
if [ ! -f "dist/index.js" ]; then
  echo "Error: Build failed - dist/index.js not found"
  exit 1
fi
