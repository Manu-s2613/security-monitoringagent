#!/bin/bash

# AI-Based Cloud Security Monitoring System
# Quick Start Setup Script

echo "============================================================"
echo "🛡️  AI-Based Cloud Security Monitoring System"
echo "============================================================"
echo ""

# Step 1: Install dependencies
echo "📦 Installing Python dependencies..."
pip install -r requirements.txt

echo ""
echo "✓ Dependencies installed successfully"
echo ""

# Step 2: Generate datasets
echo "🤖 Generating sample data and training ML model..."
cd ml
python3 anomaly_detection.py
cd ..

echo ""
echo "✓ Data generation complete"
echo ""

# Step 3: Instructions
echo "============================================================"
echo "✅ Setup Complete!"
echo "============================================================"
echo ""
echo "To start the application:"
echo ""
echo "  1. cd backend"
echo "  2. python3 app.py"
echo "  3. Open browser to: http://127.0.0.1:5000"
echo ""
echo "============================================================"
echo "📚 Documentation: See README.md for full details"
echo "============================================================"
