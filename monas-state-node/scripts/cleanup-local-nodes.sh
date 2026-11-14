#!/bin/bash

# Monas State Node - cleanup script
# Stops running nodes and deletes data files

set -e

# Color output definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Move to the State Node directory
STATE_NODE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$STATE_NODE_DIR"

log_info "State Node directory: $STATE_NODE_DIR"

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}      Starting State Node cleanup       ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check the PID file
PID_FILE="$STATE_NODE_DIR/.local-nodes.pids"

# Stop running nodes
if [ -f "$PID_FILE" ]; then
    log_info "Stopping running nodes..."

    while IFS= read -r pid; do
        if [ -n "$pid" ]; then
            if kill -0 "$pid" 2>/dev/null; then
                log_info "Stopping process PID $pid..."
                kill "$pid" 2>/dev/null || true

                # Wait for the process to exit (up to 5 seconds)
                for i in {1..10}; do
                    if ! kill -0 "$pid" 2>/dev/null; then
                        log_info "PID $pid stopped"
                        break
                    fi
                    if [ $i -eq 10 ]; then
                        log_warn "PID $pid did not stop gracefully. Force killing..."
                        kill -9 "$pid" 2>/dev/null || true
                    fi
                    sleep 0.5
                done
            else
                log_info "PID $pid is already stopped"
            fi
        fi
    done < "$PID_FILE"

    rm -f "$PID_FILE"
    log_info "Deleted the PID file"
else
    log_info "PID file not found. No nodes appear to be running"
fi

# Check whether the ports are in use
log_info "Checking port usage..."
for port in 8080 8081 8082 8083; do
    if lsof -i:$port > /dev/null 2>&1; then
        log_warn "Port $port is still in use"
        # Show the processes using the port
        lsof -i:$port || true
    else
        log_info "Port $port is free"
    fi
done

# Delete data directories
if [ "$1" = "--all" ] || [ "$1" = "--data" ]; then
    log_warn "Deleting data directories..."

    for node in node1 node2 node3 node4; do
        if [ -d "data/$node" ]; then
            rm -rf "data/$node"
            log_info "Deleted data/$node"
        else
            log_info "data/$node does not exist"
        fi
    done

    # Delete the data directory if it is empty
    if [ -d "data" ]; then
        if [ -z "$(ls -A data 2>/dev/null)" ]; then
            rmdir "data"
            log_info "Deleted the data directory"
        fi
    fi
else
    log_info "Data directories are kept (use the --data option to delete them)"
fi

# Delete log files
if [ "$1" = "--all" ] || [ "$1" = "--logs" ]; then
    log_warn "Deleting log files..."

    if [ -d "logs" ]; then
        rm -f logs/node*.log
        log_info "Deleted the log files"

        # Delete the logs directory if it is empty
        if [ -z "$(ls -A logs 2>/dev/null)" ]; then
            rmdir "logs"
            log_info "Deleted the logs directory"
        fi
    else
        log_info "The logs directory does not exist"
    fi
else
    log_info "Log files are kept (use the --logs option to delete them)"
fi

# Delete everything
if [ "$1" = "--all" ]; then
    log_info "All test data has been cleaned up"
fi

# Check for processes
log_info "Checking for remaining processes..."
remaining_processes=false

for pattern in "state-node" "state_node"; do
    if pgrep -f "$pattern" > /dev/null 2>&1; then
        log_warn "$pattern processes are still running:"
        pgrep -f "$pattern" -l || true
        remaining_processes=true
    fi
done

if [ "$remaining_processes" = false ]; then
    log_info "All State Node processes have stopped"
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}           Cleanup complete             ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Show usage
if [ -z "$1" ]; then
    echo "Usage:"
    echo "  $0           # Stop nodes only"
    echo "  $0 --data    # Stop nodes and delete data"
    echo "  $0 --logs    # Stop nodes and delete logs"
    echo "  $0 --all     # Delete everything (data and logs)"
    echo ""
fi

exit 0