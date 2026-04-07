#!/usr/bin/env bash
# Optional helper for the Docker analysis lab (see README.md).
set -e
cd "$(dirname "$0")"

case "${1:-help}" in
  build)
    echo "Building analysis container (first run may take several minutes)..."
    docker compose build
    echo "Done. Run './lab.sh shell' for an interactive shell."
    ;;

  start|shell)
    if ! docker compose ps --status running 2>/dev/null | grep -q malware-lab; then
      echo "Starting container..."
      docker compose up -d
    fi
    echo ""
    echo "Sample:  /lab/sample/installer_binary (read-only, host: ./sample/)"
    echo "Output:  /lab/output/  -> ./output/"
    echo "Scripts: /lab/scripts/ -> ./scripts/"
    echo "Network: disabled in docker-compose.yml"
    echo ""
    echo "Decrypt config:  python3 /lab/scripts/decrypt_all.py"
    echo "Static analysis: python3 /lab/scripts/analyze.py full"
    echo ""
    docker compose exec lab /bin/bash
    ;;

  stop)
    docker compose down
    ;;

  status)
    docker compose ps
    ;;

  clean)
    echo "Stopping container and removing local image..."
    docker compose down --rmi local -v
    echo "Clean complete. Sample under ./sample/ is unchanged."
    ;;

  help|*)
    echo "Usage: ./lab.sh [build|shell|stop|status|clean]"
    echo "See README.md for full documentation."
    ;;
esac
