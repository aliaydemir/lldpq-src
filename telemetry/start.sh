#!/bin/bash
# Start LLDPq Telemetry Stack (OTEL Collector + Prometheus + Alertmanager)
# Usage: ./start.sh [start|stop|restart|status|logs]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Prefer compose v2 plugin ('docker compose'), fall back to legacy v1 binary
if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose"
else
    COMPOSE="docker-compose"
fi

case "${1:-start}" in
    start)
        echo "Starting LLDPq Telemetry Stack..."
        $COMPOSE up -d
        echo ""
        echo "Services started:"
        echo "  - OTEL Collector: http://localhost:4317 (gRPC), http://localhost:4318 (HTTP)"
        echo "  - Prometheus:     http://localhost:9090"
        echo "  - Alertmanager:   http://localhost:9093"
        echo ""
        echo "To view logs: ./start.sh logs"
        ;;
    stop)
        echo "Stopping LLDPq Telemetry Stack..."
        $COMPOSE down
        ;;
    restart)
        echo "Restarting LLDPq Telemetry Stack..."
        $COMPOSE restart
        ;;
    status)
        $COMPOSE ps
        ;;
    logs)
        $COMPOSE logs -f --tail=100
        ;;
    *)
        echo "Usage: $0 [start|stop|restart|status|logs]"
        exit 1
        ;;
esac
