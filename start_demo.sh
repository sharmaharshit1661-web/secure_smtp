#!/usr/bin/env bash
# ==============================================================================
# Secure SMTP — Demo & Presentation Launcher
# ==============================================================================
# Launches both the FastAPI backend and React web console with 1 command.
# Seeds sample data if needed.
# ==============================================================================

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "======================================================================"
echo "🛡️ Secure SMTP — Cryptographic Security Posture Assessment"
echo "======================================================================"

# 1. Activate Virtual Environment
if [ -d ".venv" ]; then
    echo "✓ Activating virtual environment (.venv)..."
    source .venv/bin/activate
elif [ -d "venv" ]; then
    echo "✓ Activating virtual environment (venv)..."
    source venv/bin/activate
else
    echo "⚠️ No virtual environment found. Using system python3."
fi

# 2. Configure Database & API Authentication Credentials
export SECURE_SMTP_API_KEY="${SECURE_SMTP_API_KEY:-securesmtp_live_secret_key}"
export SECURE_SMTP_MONGO_USER="${SECURE_SMTP_MONGO_USER:-secure_admin}"
export SECURE_SMTP_MONGO_PASSWORD="${SECURE_SMTP_MONGO_PASSWORD:-secure_smtp_live_db_key_2026}"
export SECURE_SMTP_MONGO_AUTH_DB="${SECURE_SMTP_MONGO_AUTH_DB:-admin}"
export SECURE_SMTP_MONGO_AUTH_MECHANISM="${SECURE_SMTP_MONGO_AUTH_MECHANISM:-SCRAM-SHA-256}"

# 3. Check/Generate Test PCAPs & Seed Demo Data
echo "✓ Checking demo database (MongoDB)..."
PYTHONPATH=src python scripts/seed_demo_data.py

# 3. Clean up existing processes on ports 8000 and 5173 if any
echo "✓ Checking ports..."
lsof -ti:8000 | xargs kill -9 2>/dev/null || true
lsof -ti:5173 | xargs kill -9 2>/dev/null || true

# 4. Start FastAPI Backend
echo "✓ Starting FastAPI backend on http://localhost:8000..."
PYTHONPATH=src uvicorn secure_smtp.api.main:app --host 0.0.0.0 --port 8000 --log-level warning &
BACKEND_PID=$!

# Wait for backend to be ready
echo "✓ Waiting for backend initialization..."
for i in {1..30}; do
    if curl -s http://localhost:8000/api/health >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done

# 5. Start React Frontend
echo "✓ Starting React Web Application on http://localhost:5173..."
(cd frontend && npm run dev -- --host 0.0.0.0 --port 5173) &
FRONTEND_PID=$!

# 6. Presentation Ready Banner
echo ""
echo "======================================================================"
echo "🚀 Secure SMTP is LIVE and ready for presentation!"
echo "======================================================================"
echo "  🌐 Web Console:          http://localhost:5173"
echo "  📡 FastAPI Backend:      http://localhost:8000"
echo "  📚 Swagger API Docs:     http://localhost:8000/docs"
echo "  🔐 API Auth:             Enabled (Key: ${SECURE_SMTP_API_KEY:0:12}***)"
echo "  🗄️ MongoDB Auth:         Active (${SECURE_SMTP_MONGO_USER}@${SECURE_SMTP_MONGO_AUTH_DB})"
echo "  📁 Demo PCAPs Location:  $PROJECT_ROOT/tests/fixtures/pcaps/"
echo "======================================================================"
echo "Press Ctrl+C to stop all servers."
echo ""

# Trap SIGINT / SIGTERM for clean shutdown
cleanup() {
    echo ""
    echo "Shutting down servers..."
    kill $BACKEND_PID 2>/dev/null || true
    kill $FRONTEND_PID 2>/dev/null || true
    echo "✓ All servers stopped. Good luck with the judges!"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Wait on background processes
wait
