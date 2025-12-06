#!/bin/bash
# Build script for Railway

# Install frontend dependencies and build
cd frontend
npm install
npm run build
cd ..

# The frontend build will be in frontend/dist
echo "Frontend built successfully"
