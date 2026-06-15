# SELinux Repeated Denial Alert - Testing Instructions

This document describes how to test the SELinuxRepeatedDenialAlertEventID feature.

## Feature Overview

The SELinux repeated denial alert detects when a process triggers multiple SELinux denials within a time window, which may indicate:
- A malicious application probing for exploitable permissions
- A misconfigured application repeatedly attempting unauthorized operations
- A potential privilege escalation attempt

### Alert Parameters
- **Threshold**: 5 denials from the same process
- **Time Window**: 30 seconds
- **Cooldown**: 60 seconds between alerts for the same key

### Two Detection Modes

1. **SELinuxDenialEventID (1019)**: Low-level kernel detection via `security_inode_permission` kprobe. Captures all SELinux permission denials at the kernel level.

2. **SELinuxProtectedResourceAccessAlertEventID (1018)**: High-level detection for accesses to protected resources (SELinux policy files, etc.) with DENIED result.

Both modes feed into the same denial tracker to generate `SELinuxRepeatedDenialAlertEventID` (1020) alerts.

## Build Instructions

### 1. Compile the eBPF code

```bash
# On the target Android device or build environment
cd /path/to/BPFroid-main

# Compile the eBPF object file
make bpf

# Or full rebuild
make clean
make
```

### 2. Verify kernel symbol availability

```bash
# Check if security_inode_permission is available
adb shell cat /proc/kallsyms | grep security_inode_permission

# Expected output (address may vary):
# ffffffc000123456 T security_inode_permission
```

If the symbol is not found, the kernel may not have eBPF kprobe support enabled or the symbol is not exported.

## Running the Tool

### Enable SELinux denial alerts

```bash
# Run with security alerts enabled (includes SELinux denial detection)
./tracee --security-alerts

# Or run with specific events
./tracee --trace selinux_denial --trace selinux_repeated_denial_alert

# With JSON output for easier parsing
./tracee --security-alerts --output json
```

## Generating Test Denials

### Method 1: Read protected files (requires SELinux enforcing mode)

```bash
# On Android device, try to read files from another app's private directory
adb shell
cat /data/data/com.android.settings/databases/settings.db

# Or try to read SELinux-protected system files
cat /sys/fs/selinux/policy
```

### Method 2: Use a test application

Create an Android app that repeatedly attempts unauthorized operations:

```java
// Example Java code for test app
for (int i = 0; i < 10; i++) {
    try {
        Runtime.getRuntime().exec("cat /data/system/packages.xml");
    } catch (Exception e) {
        // Expected to fail with permission denied
    }
    Thread.sleep(100); // Small delay between attempts
}
```

### Method 3: Use shell script to trigger denials

```bash
#!/system/bin/sh
# rapid_access.sh - Run this to trigger multiple SELinux denials
for i in $(seq 1 10); do
    cat /data/system/packages.xml 2>/dev/null
    ls /data/data/com.android.providers.contacts/ 2>/dev/null
done
```

## Expected Output

### Individual SELinux Denial Events (Event ID 1019)

```
TIME             UID    COMM             PID    TID    RET    EVENT              ARGS
1234567890.123   10001  testapp          1234   1234   -13    selinux_denial    pathname=/data/system/packages.xml mask=MAY_READ(4) ret=EACCES(-13) dev=253:2 inode=12345
```

### Repeated Denial Alert (Event ID 1020)

After 5+ denials within 30 seconds from the same process:

```
TIME             UID    COMM             PID    TID    RET    EVENT                           ARGS
1234567890.456   10001  testapp          1234   1234   0      selinux_repeated_denial_alert  process_name=testapp pid=1234 tgid=1234 uid=10001 last_denied_path=/data/system/packages.xml last_operation=MAY_READ(4) denial_count=5 time_window_secs=30 threshold=5 ...
```

### JSON Output Format

```json
{
  "timestamp": 1234567890.123,
  "processId": 1234,
  "threadId": 1234,
  "userId": 10001,
  "processName": "testapp",
  "eventId": 1020,
  "eventName": "selinux_repeated_denial_alert",
  "args": [
    {"name": "process_name", "type": "const char*", "value": "testapp"},
    {"name": "pid", "type": "int", "value": 1234},
    {"name": "tgid", "type": "int", "value": 1234},
    {"name": "uid", "type": "unsigned int", "value": 10001},
    {"name": "last_denied_path", "type": "const char*", "value": "/data/system/packages.xml"},
    {"name": "last_operation", "type": "const char*", "value": "MAY_READ(4)"},
    {"name": "denial_count", "type": "unsigned int", "value": "5 denials in 30s"},
    {"name": "time_window_secs", "type": "unsigned int", "value": 30},
    {"name": "threshold", "type": "unsigned int", "value": 5},
    {"name": "first_denial_ts", "type": "unsigned long", "value": 1234567800000000},
    {"name": "last_denial_ts", "type": "unsigned long", "value": 1234567890123000},
    {"name": "cooldown_state", "type": "const char*", "value": "ALERT_TRIGGERED"}
  ]
}
```

## Verification Steps

1. **Start tracee with security alerts**
   ```bash
   ./tracee --security-alerts --output json > /data/local/tmp/tracee_output.json &
   ```

2. **Trigger denials** (use any method above)

3. **Check for individual denial events** (Event ID 1019)
   ```bash
   grep "selinux_denial" /data/local/tmp/tracee_output.json
   ```

4. **Check for repeated denial alerts** (Event ID 1020)
   ```bash
   grep "selinux_repeated_denial_alert" /data/local/tmp/tracee_output.json
   ```

5. **Verify cooldown behavior**
   - After an alert is generated, subsequent denials from the same process should not trigger new alerts for 60 seconds

## Troubleshooting

### No events appearing

1. **Check SELinux mode**
   ```bash
   adb shell getenforce
   # Should return "Enforcing" for denials to occur
   ```

2. **Verify kprobe attachment**
   ```bash
   adb shell cat /sys/kernel/debug/kprobes/list | grep security_inode_permission
   ```

3. **Check BPF program loading**
   ```bash
   adb shell bpftool prog list | grep -i selinux
   ```

### Too many events

Adjust the threshold/window in `tracee.go`:
```go
// In New() function
t.selinuxDenialTracker = NewSELinuxDenialTracker(10, 60, 120)
// threshold=10 denials, window=60s, cooldown=120s
```

## Architecture Notes

### eBPF Side (tracee.bpf.c)
- `kprobe/security_inode_permission`: Captures entry parameters (inode, mask)
- `kretprobe/security_inode_permission`: Checks return value; only emits event if retval < 0 (denied)

### Userspace Side (tracee.go, pipeline.go)
- `SELinuxDenialTracker`: Maintains per-process denial counts with timestamps
- `SELinuxDenialKey`: Unique identifier combining PID, UID, ProcessName, Operation, PathPrefix
- `RecordDenial()`: Adds denial to tracker, returns alert info if threshold reached
- `checkAndRecordSELinuxDenial()`: Handles SELinuxProtectedResourceAccessAlertEventID events
- `checkAndRecordSELinuxInodeDenial()`: Handles SELinuxDenialEventID events from kprobe

### Event Flow
1. Kernel: `security_inode_permission()` returns negative value (denied)
2. eBPF: kretprobe captures denial, sends `SELinuxDenialEventID` (1019)
3. Userspace: `prepareEventForPrint()` receives denial, calls tracker
4. If threshold reached: Synthetic `SELinuxRepeatedDenialAlertEventID` (1020) injected
5. Both events printed to output
