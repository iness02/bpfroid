#!/system/bin/sh
# Test script for IP Change Alert
# Run this on the Android device

echo "========================================"
echo "  BPFroid IP Change Alert Test Script"
echo "========================================"
echo ""

# Colors for output (may not work on all terminals)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo "[INFO] $1"
}

log_pass() {
    echo "[PASS] $1"
}

log_fail() {
    echo "[FAIL] $1"
}

log_warn() {
    echo "[WARN] $1"
}

# Step 1: Check if running as root
echo "=== Step 1: Checking root access ==="
if [ "$(id -u)" != "0" ]; then
    log_fail "Not running as root. Run: su -c 'sh test_ip_alert.sh'"
    exit 1
fi
log_pass "Running as root"
echo ""

# Step 2: Check kernel symbols for IP functions
echo "=== Step 2: Checking kernel symbols ==="
echo "Looking for IP address change functions..."

if grep -q "inet_rtm_newaddr" /proc/kallsyms; then
    INET_RTM=$(grep "inet_rtm_newaddr" /proc/kallsyms | head -1)
    log_pass "inet_rtm_newaddr found: $INET_RTM"
else
    log_fail "inet_rtm_newaddr NOT found in kallsyms"
fi

if grep -q "__inet_insert_ifa" /proc/kallsyms; then
    INET_INSERT=$(grep "__inet_insert_ifa" /proc/kallsyms | head -1)
    log_pass "__inet_insert_ifa found: $INET_INSERT"
else
    log_warn "__inet_insert_ifa NOT found in kallsyms"
fi

if grep -q "devinet_ioctl" /proc/kallsyms; then
    DEVINET=$(grep "devinet_ioctl" /proc/kallsyms | head -1)
    log_pass "devinet_ioctl found: $DEVINET"
else
    log_warn "devinet_ioctl NOT found in kallsyms"
fi
echo ""

# Step 3: Check tracefs/debugfs mount
echo "=== Step 3: Checking tracefs mount ==="
if [ -d "/sys/kernel/tracing" ]; then
    log_pass "/sys/kernel/tracing exists"
    TRACE_DIR="/sys/kernel/tracing"
elif [ -d "/sys/kernel/debug/tracing" ]; then
    log_pass "/sys/kernel/debug/tracing exists"
    TRACE_DIR="/sys/kernel/debug/tracing"
else
    log_fail "No tracefs found. Trying to mount..."
    mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null
    if [ -d "/sys/kernel/tracing" ]; then
        TRACE_DIR="/sys/kernel/tracing"
        log_pass "Mounted tracefs at /sys/kernel/tracing"
    else
        log_fail "Could not mount tracefs"
        exit 1
    fi
fi
echo ""

# Step 4: Check current kprobes
echo "=== Step 4: Checking registered kprobes ==="
echo "Current kprobe_events:"
cat $TRACE_DIR/kprobe_events 2>/dev/null || echo "(empty or not accessible)"
echo ""

# Step 5: Check network interfaces
echo "=== Step 5: Checking network interfaces ==="
ip link show 2>/dev/null || ifconfig -a 2>/dev/null
echo ""
echo "Current IP addresses:"
ip addr show 2>/dev/null || ifconfig 2>/dev/null
echo ""

# Step 6: Test IP address operations
echo "=== Step 6: Testing IP address operations ==="
TEST_IP="10.99.99.99"
TEST_PREFIX="24"

# Find a suitable interface
IFACE=""
for iface in wlan0 eth0 rmnet0 ccmni0; do
    if ip link show $iface 2>/dev/null | grep -q "state"; then
        IFACE=$iface
        break
    fi
done

if [ -z "$IFACE" ]; then
    log_warn "No suitable interface found, using wlan0"
    IFACE="wlan0"
fi
log_info "Using interface: $IFACE"
echo ""

# Clear trace buffer
echo "" > $TRACE_DIR/trace 2>/dev/null

echo ">>> Adding test IP address: $TEST_IP/$TEST_PREFIX to $IFACE"
ip addr add $TEST_IP/$TEST_PREFIX dev $IFACE 2>&1
ADD_RESULT=$?
if [ $ADD_RESULT -eq 0 ]; then
    log_pass "ip addr add succeeded"
else
    log_warn "ip addr add returned $ADD_RESULT (may already exist or interface down)"
fi

sleep 1

echo ">>> Removing test IP address: $TEST_IP/$TEST_PREFIX from $IFACE"
ip addr del $TEST_IP/$TEST_PREFIX dev $IFACE 2>&1
DEL_RESULT=$?
if [ $DEL_RESULT -eq 0 ]; then
    log_pass "ip addr del succeeded"
else
    log_warn "ip addr del returned $DEL_RESULT"
fi
echo ""

# Step 7: Check trace output
echo "=== Step 7: Checking trace output ==="
echo "Contents of trace buffer (IP_ALERT messages):"
grep -i "IP_ALERT\|SUBMIT" $TRACE_DIR/trace 2>/dev/null | tail -50
echo ""

# Step 8: Verify kprobes after tracee
echo "=== Step 8: Checking kprobes after test ==="
echo "Registered kprobes:"
cat $TRACE_DIR/kprobe_events 2>/dev/null
echo ""

# Summary
echo "========================================"
echo "              TEST SUMMARY"
echo "========================================"
echo "Kernel functions:"
grep -c "inet_rtm_newaddr" /proc/kallsyms > /dev/null && echo "  inet_rtm_newaddr: FOUND" || echo "  inet_rtm_newaddr: NOT FOUND"
grep -c "__inet_insert_ifa" /proc/kallsyms > /dev/null && echo "  __inet_insert_ifa: FOUND" || echo "  __inet_insert_ifa: NOT FOUND"
grep -c "devinet_ioctl" /proc/kallsyms > /dev/null && echo "  devinet_ioctl: FOUND" || echo "  devinet_ioctl: NOT FOUND"
echo ""
echo "To run BPFroid with logging, use these commands:"
echo ""
echo "  Terminal 1 (watch logs):"
echo "    cat $TRACE_DIR/trace_pipe"
echo ""
echo "  Terminal 2 (run tracee):"
echo "    cd /data/local/tmp/bpfroid && ./tracee --security-alerts"
echo ""
echo "  Terminal 3 (trigger IP change):"
echo "    ip addr add 10.99.99.99/24 dev $IFACE"
echo ""
echo "========================================"
