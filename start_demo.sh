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

# 2. Load Environment Configuration (.env) if present
if [ -f ".env" ]; then
    echo "✓ Loading configuration from .env..."
    set -a
    source .env
    set +a
fi

# Provision real login before launching. Do not create demo identities.
if [ -z "${SECURE_SMTP_LOCAL_PASSWORD_HASH:-}" ] && [ -z "${SECURE_SMTP_CLERK_ISSUER:-}" ]; then
    echo "Configure authentication first: PYTHONPATH=src python scripts/provision_local_operator.py"
    exit 1
fi

# Refuse occupied ports instead of killing unrelated processes.
for port in 8000 5173; do
    if lsof -tiTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
        echo "Port $port is in use. Stop the existing server before launching."
        exit 1
    fi
done

# Seed only when explicitly requested; existing customer data is preserved.
if [ "${SECURE_SMTP_SEED_DEMO:-false}" = "true" ]; then
    PYTHONPATH=src python scripts/seed_demo_data.py
fi

# 4. Start FastAPI Backend
echo "✓ Starting FastAPI backend on http://localhost:8000..."
PYTHONPATH=src uvicorn secure_smtp.api.main:app --host 127.0.0.1 --port 8000 --log-level warning &
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
(cd frontend && npm run dev -- --host 127.0.0.1 --port 5173) &
FRONTEND_PID=$!

# 6. Presentation Ready Banner
echo ""
echo "======================================================================"
echo "🚀 Secure SMTP is LIVE and ready for presentation!"
echo "======================================================================"
echo "  🌐 Web Console:          http://localhost:5173"
echo "  📡 FastAPI Backend:      http://localhost:8000"
echo "  📚 Swagger API Docs:     http://localhost:8000/docs"
echo "  🔐 Authentication:       Verified operator sessions"
echo "  🗄️ MongoDB:              Configured through .env"
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
