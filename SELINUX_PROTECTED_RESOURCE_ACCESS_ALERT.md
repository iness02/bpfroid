# SELinux Protected Resource Access Alert

This document describes the implementation and testing of the `SELinuxProtectedResourceAccessAlertEventID` feature.

## Overview

The SELinux Protected Resource Access Alert detects when a process attempts to access SELinux-protected or sensitive Android resources. This is useful for detecting potential privilege escalation attempts, unauthorized data access, or malicious reconnaissance activity.

## Sensitive Path Matching

The alert triggers when access is attempted to paths matching these prefixes:

| Prefix | Description | Example Paths |
|--------|-------------|---------------|
| `/data/system/` | System configuration and package data | `/data/system/packages.xml`, `/data/system/users/0/settings_secure.xml` |
| `/data/misc/keystore` | Android keystore credentials | `/data/misc/keystore/user_0/.masterkey` |
| `/dev/` | Device nodes (hardware access) | `/dev/block/sda1`, `/dev/input/event0`, `/dev/kgsl-3d0` |
| `/system/bin/` | System binaries | `/system/bin/sh`, `/system/bin/su`, `/system/bin/setenforce` |

## Event ID

- **Event ID**: 1018 (SELinuxProtectedResourceAccessAlertEventID)
- **Event Name**: `selinux_protected_resource_access_alert`

## Alert Fields

The alert provides the following information:

| Field | Type | Description |
|-------|------|-------------|
| `syscall_name` | string | The syscall that triggered the access (open, openat, access, faccessat) |
| `pathname` | string | The full path being accessed |
| `matched_prefix` | string | Which sensitive prefix was matched |
| `access_type` | uint32 | Type of access: 1=read, 2=write, 3=execute, 4=stat/check, 5=unknown |
| `flags_or_mode` | int | Open flags or access mode passed to the syscall |
| `retval` | int | Syscall return value (negative = error) |
| `result` | uint32 | 0=DENIED, 1=ALLOWED |

## Detection Algorithm

### Step-by-Step Flow

1. **Syscall Capture**
   - The eBPF program hooks into `security_file_open` (kprobe) for successful file opens
   - The eBPF program hooks into `raw_tracepoint/sys_exit` for failed syscalls
   - Monitored syscalls: `open`, `openat`, `access`, `faccessat`, `faccessat2`

2. **Path Extraction**
   - For `open/openat`: Path is extracted from syscall arguments
   - For `security_file_open`: Path is extracted from the `struct file` parameter

3. **Sensitive Path Matching**
   - The `get_sensitive_path_type()` function checks if the path starts with any sensitive prefix
   - Returns: 1=/data/system/, 2=/data/misc/keystore, 3=/dev/, 4=/system/bin/, 0=no match

4. **Access Type Detection**
   - For open/openat: Based on flags (O_RDONLY=read, O_WRONLY/O_RDWR=write)
   - For access/faccessat: Classified as stat/check operation

5. **Result Determination**
   - **ALLOWED**: Detected in `security_file_open` kprobe (before denial could happen)
   - **DENIED**: Detected in `sys_exit` tracepoint with negative return value

6. **Alert Emission**
   - Alert is submitted through the perf buffer with all collected fields
   - Userspace receives and prints the alert

### Deduplication

The current implementation does not include built-in deduplication. To avoid excessive alerts:
- Consider filtering `/dev/` matches in production (many normal processes access device nodes)
- Use external log aggregation with deduplication
- Future enhancement: Add per-process cooldown in eBPF maps

### Backward Compatibility

This implementation is fully backward-compatible:
- New event ID (1018) does not conflict with existing events
- Existing alerts (SELinux mode change, policy reload, write alert, etc.) continue to work unchanged
- No changes to existing event argument ordering
- New alert is independently enabled with `--security-alerts`

## Configuration

### hooks.json

Required syscall hooks (minimal version):
```json
{
  "hookConfigs": {
    "syscalls": [
      {"name": "open"},
      {"name": "openat"},
      {"name": "access"},
      {"name": "faccessat"}
    ]
  }
}
```

Extended version (optional additional coverage):
```json
{
  "hookConfigs": {
    "syscalls": [
      {"name": "open"},
      {"name": "openat"},
      {"name": "access"},
      {"name": "faccessat"},
      {"name": "stat"},
      {"name": "newfstatat"},
      {"name": "execve"}
    ]
  }
}
```

### Running with --security-alerts

```bash
./tracee --security-alerts
```

Or with output format:
```bash
./tracee --security-alerts --output json
./tracee --security-alerts --output table
```

## Build Instructions

1. Build the eBPF program:
```bash
make clean
make bpf
```

2. Build the tracee binary:
```bash
make
```

Or build everything:
```bash
make all
```

## Testing Instructions

### Commands That SHOULD Trigger Alerts

#### Access to /data/system/
```bash
cat /data/system/packages.xml
ls /data/system/
stat /data/system/packages.list
```

Expected output (table format):
```
selinux_protected_resource_access_alert  syscall_name: openat, pathname: /data/system/packages.xml, matched_prefix: /data/system/, access_type: read, flags_or_mode: 0, retval: -13, result: DENIED
```

#### Access to /data/misc/keystore
```bash
cat /data/misc/keystore/user_0/*
ls /data/misc/keystore/
```

Expected output:
```
selinux_protected_resource_access_alert  syscall_name: openat, pathname: /data/misc/keystore/user_0/.masterkey, matched_prefix: /data/misc/keystore, access_type: read, flags_or_mode: 0, retval: -13, result: DENIED
```

#### Access to /dev/
```bash
ls /dev/
cat /dev/input/event0
cat /dev/block/sda1
```

Expected output:
```
selinux_protected_resource_access_alert  syscall_name: openat, pathname: /dev/input/event0, matched_prefix: /dev/, access_type: read, flags_or_mode: 0, retval: 3, result: ALLOWED
```

#### Access to /system/bin/
```bash
ls /system/bin/
cat /system/bin/sh
/system/bin/sh -c "echo test"
```

Expected output:
```
selinux_protected_resource_access_alert  syscall_name: openat, pathname: /system/bin/sh, matched_prefix: /system/bin/, access_type: read, flags_or_mode: 0, retval: 3, result: ALLOWED
```

### Commands That Should NOT Trigger Alerts

```bash
cat /data/local/tmp/test.txt
ls /sdcard/
touch /data/local/tmp/normal_file
ls /system/lib/
cat /etc/hosts
```

### JSON Output Example

With `--output json`:

**Allowed Access:**
```json
{
  "timestamp": 1234567890.123,
  "processId": 1234,
  "processName": "cat",
  "eventId": "1018",
  "eventName": "selinux_protected_resource_access_alert",
  "returnValue": 3,
  "args": [
    {"name": "syscall_name", "value": "openat"},
    {"name": "pathname", "value": "/system/bin/sh"},
    {"name": "matched_prefix", "value": "/system/bin/"},
    {"name": "access_type", "value": "read"},
    {"name": "flags_or_mode", "value": 0},
    {"name": "retval", "value": 3},
    {"name": "result", "value": "ALLOWED"}
  ]
}
```

**Denied Access:**
```json
{
  "timestamp": 1234567890.456,
  "processId": 1234,
  "processName": "cat",
  "eventId": "1018",
  "eventName": "selinux_protected_resource_access_alert",
  "returnValue": -13,
  "args": [
    {"name": "syscall_name", "value": "openat"},
    {"name": "pathname", "value": "/data/system/packages.xml"},
    {"name": "matched_prefix", "value": "/data/system/"},
    {"name": "access_type", "value": "read"},
    {"name": "flags_or_mode", "value": 0},
    {"name": "retval", "value": -13},
    {"name": "result", "value": "DENIED"}
  ]
}
```

## Troubleshooting

### Alert Not Appearing

1. **Verify the alert is enabled:**
   ```bash
   ./tracee --security-alerts --trace selinux_protected_resource_access_alert
   ```

2. **Check hooks.json:**
   - Ensure `open`, `openat`, `access` syscalls are listed
   - Verify JSON syntax is correct

3. **Check if target path matches sensitive prefixes:**
   - Path must start with one of: `/data/system/`, `/data/misc/keystore`, `/dev/`, `/system/bin/`
   - Matching is prefix-based, not substring

4. **Check kernel version:**
   - eBPF features require Linux 4.x+ kernel
   - Raw tracepoints require Linux 4.17+

5. **Check permissions:**
   - Tracee needs root/CAP_SYS_ADMIN to load eBPF programs

### Too Many Alerts

1. **Filter /dev/ alerts:**
   - Many normal processes access device nodes
   - Consider disabling /dev/ matching in production or filtering in post-processing

2. **Use deduplication:**
   - Pipe output through `uniq` or use log aggregation

### Error Codes Reference

Common `retval` values for denied access:
- `-13` (EACCES): Permission denied
- `-1` (EPERM): Operation not permitted
- `-2` (ENOENT): No such file or directory

## Security Considerations

This alert helps detect:
- **Privilege escalation attempts**: Accessing `/data/system/` to read/modify system configuration
- **Credential theft**: Accessing `/data/misc/keystore` to steal cryptographic keys
- **Device probing**: Accessing `/dev/` to interact with hardware directly
- **Binary tampering**: Accessing `/system/bin/` to modify or replace system binaries

Note: Successful access to these paths (result=ALLOWED) by an untrusted process is as concerning as failed attempts, as it may indicate elevated privileges or SELinux policy issues.

## Related Alerts

This alert complements existing SELinux-related alerts:
- `SELinuxModeChangeAlertEventID` (1016): Detects SELinux mode changes
- `SELinuxPolicyReloadAlertEventID` (1017): Detects SELinux policy reloads
- `WriteAlertEventID` (1014): Detects dropper activity (ELF/APK/DEX writes)

## Future Enhancements

Planned improvements:
1. Built-in deduplication with configurable cooldown
2. Configurable sensitive path list
3. Detection of `stat`, `newfstatat`, `execve` syscalls
4. Process context enrichment (SELinux context, app package name)
5. Alerting for specific error codes (EACCES, EPERM)
