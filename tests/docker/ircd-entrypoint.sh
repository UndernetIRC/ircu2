#!/bin/bash
# Launch ircd for integration tests. Set IRCD_DEBUG=gdb|valgrind to wrap the
# binary and write diagnostics under /opt/ircu/debug (bind-mounted by compose).
#
# Runs as root so core_pattern and debug dir permissions can be configured,
# then drops to the ircu user for the daemon (unless using live gdb).
set -euo pipefail

IRCD="/opt/ircu/bin/ircd"
CONF="/opt/ircu/lib/ircd.conf"
DEBUG_DIR="/opt/ircu/debug"

setup_debug_dir() {
  mkdir -p "$DEBUG_DIR"
  chmod 777 "$DEBUG_DIR"
}

setup_cores() {
  ulimit -c unlimited 2>/dev/null || true
  if [ -w /proc/sys/kernel/core_pattern ]; then
    echo "${DEBUG_DIR}/core.%e.%p" > /proc/sys/kernel/core_pattern
  fi
}

timestamp() { date -Iseconds 2>/dev/null || date; }

run_as_ircu() {
  su -s /bin/bash ircu -c "cd /opt/ircu && exec $(printf '%q ' "$@")"
}

run_normal() {
  # Honor docker CMD / compose `command:` args (e.g. -x 8 for DEBUGMODE).
  if [ "$#" -eq 0 ]; then
    set -- -f "$CONF" -n
  fi
  run_as_ircu "$IRCD" "$@"
}

run_gdb() {
  local log="$DEBUG_DIR/gdb.log"
  {
    echo "=== ircd gdb session $(timestamp) ==="
    echo "IRCD_DEBUG=gdb"
    echo "command: $IRCD -f $CONF -n"
    echo
  } | tee "$log"
  # Live gdb under ircu; cores still land in DEBUG_DIR if gdb misses a fault.
  su -s /bin/bash ircu -c "cd /opt/ircu && gdb -batch \
    -ex 'set pagination off' \
    -ex 'run -f $CONF -n' \
    -ex 'thread apply all bt full' \
    -ex 'info registers' \
    -ex 'quit' \
    --args $IRCD -f $CONF -n" 2>&1 | tee -a "$log"
  exit "${PIPESTATUS[0]}"
}

run_valgrind() {
  local log="$DEBUG_DIR/valgrind.log"
  {
    echo "=== ircd valgrind session $(timestamp) ==="
    echo "IRCD_DEBUG=valgrind"
    echo "command: $IRCD -f $CONF -n"
    echo
  } >"$DEBUG_DIR/valgrind-meta.log"
  ulimit -n 4096 2>/dev/null || ulimit -n 1024
  run_as_ircu valgrind \
    --error-exitcode=99 \
    --leak-check=full \
    --track-origins=yes \
    --show-error-list=yes \
    --gen-suppressions=all \
    --log-file="$log" \
    "$IRCD" -f "$CONF" -n \
    2>&1 | tee "$DEBUG_DIR/valgrind-stdout.log"
  exit "${PIPESTATUS[0]}"
}

setup_debug_dir
setup_cores

case "${IRCD_DEBUG:-}" in
  gdb) run_gdb ;;
  valgrind) run_valgrind ;;
  ""|normal) run_normal "$@" ;;
  *)
    echo "ircd-entrypoint: unknown IRCD_DEBUG=${IRCD_DEBUG}" >&2
    exit 2
    ;;
esac
