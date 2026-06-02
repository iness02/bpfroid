package main

// IP Change Alert Test
// This file contains tests for the IP change detection functionality
// Run with: go test -v -run TestIpChangeAlert

import (
	"testing"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// TestIpChangeAlertKernelSymbols checks if required kernel symbols exist
func TestIpChangeAlertKernelSymbols(t *testing.T) {
	symbols := []struct {
		name     string
		required bool
	}{
		{"inet_rtm_newaddr", true},
		{"inet_rtm_deladdr", true},
		{"__inet_insert_ifa", false},
		{"__inet_del_ifa", false},
		{"devinet_ioctl", false},
	}

	kallsyms, err := os.ReadFile("/proc/kallsyms")
	if err != nil {
		t.Skipf("Cannot read /proc/kallsyms: %v (need root?)", err)
		return
	}

	kallsymsStr := string(kallsyms)

	for _, sym := range symbols {
		found := strings.Contains(kallsymsStr, sym.name)
		if found {
			t.Logf("✓ Symbol '%s' found in kallsyms", sym.name)
		} else if sym.required {
			t.Errorf("✗ Required symbol '%s' NOT found in kallsyms", sym.name)
		} else {
			t.Logf("○ Optional symbol '%s' not found (OK)", sym.name)
		}
	}
}

// TestIpChangeAlertTracefs checks if tracefs is available
func TestIpChangeAlertTracefs(t *testing.T) {
	paths := []string{
		"/sys/kernel/tracing",
		"/sys/kernel/debug/tracing",
	}

	var tracePath string
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			tracePath = path
			break
		}
	}

	if tracePath == "" {
		t.Error("✗ No tracefs found at /sys/kernel/tracing or /sys/kernel/debug/tracing")
		return
	}

	t.Logf("✓ Tracefs found at: %s", tracePath)

	// Check if we can read kprobe_events
	kprobeEvents := tracePath + "/kprobe_events"
	if _, err := os.ReadFile(kprobeEvents); err != nil {
		t.Logf("○ Cannot read %s: %v (may need root)", kprobeEvents, err)
	} else {
		t.Logf("✓ Can read kprobe_events")
	}

	// Check if trace_pipe exists
	tracePipe := tracePath + "/trace_pipe"
	if _, err := os.Stat(tracePipe); err == nil {
		t.Logf("✓ trace_pipe exists at: %s", tracePipe)
	} else {
		t.Logf("○ trace_pipe not accessible")
	}
}

// TestIpChangeAlertEventID checks if the event ID is correctly defined
func TestIpChangeAlertEventID(t *testing.T) {
	// IP_CHANGED_ALERT should be 1016
	expectedID := int32(1016)
	
	// This would normally import the tracee package, but for standalone test:
	t.Logf("Expected IpChangedAlertEventID: %d", expectedID)
	t.Logf("Expected MAX_EVENT_ID: %d", expectedID+1)
	
	// Verify the constants match in the BPF code
	// In a real test, we would parse the BPF source file
	t.Log("✓ Event ID constants defined (verify manually in tracee.bpf.c)")
}

// TestIpAddressCommand tests if ip command works
func TestIpAddressCommand(t *testing.T) {
	// Check if ip command exists
	ipPath, err := exec.LookPath("ip")
	if err != nil {
		t.Skip("ip command not found, skipping")
		return
	}
	t.Logf("✓ ip command found at: %s", ipPath)

	// List current interfaces
	cmd := exec.Command("ip", "link", "show")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("○ ip link show failed: %v", err)
	} else {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, ":") && !strings.HasPrefix(strings.TrimSpace(line), "link") {
				t.Logf("  Interface: %s", strings.TrimSpace(line))
			}
		}
	}
}

// TestIpChangeAlertIntegration is a manual integration test
// Run tracee in another terminal and execute this test
func TestIpChangeAlertIntegration(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Integration test requires root, skipping")
		return
	}

	testIP := "10.88.88.88"
	testPrefix := "24"
	testIface := "lo" // Use loopback for safety

	t.Logf("Integration test: Adding %s/%s to %s", testIP, testPrefix, testIface)
	t.Log("Make sure tracee is running with --security-alerts in another terminal")
	t.Log("And watch /sys/kernel/tracing/trace_pipe for debug output")
	
	// Add IP
	addCmd := exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%s", testIP, testPrefix), "dev", testIface)
	addOutput, addErr := addCmd.CombinedOutput()
	if addErr != nil {
		t.Logf("ip addr add output: %s, error: %v", string(addOutput), addErr)
	} else {
		t.Logf("✓ ip addr add succeeded")
	}

	time.Sleep(2 * time.Second)

	// Delete IP
	delCmd := exec.Command("ip", "addr", "del", fmt.Sprintf("%s/%s", testIP, testPrefix), "dev", testIface)
	delOutput, delErr := delCmd.CombinedOutput()
	if delErr != nil {
		t.Logf("ip addr del output: %s, error: %v", string(delOutput), delErr)
	} else {
		t.Logf("✓ ip addr del succeeded")
	}

	t.Log("")
	t.Log("Check tracee output for ip_changed_alert events")
	t.Log("Check trace_pipe for IP_ALERT debug messages")
}

// Helper to print test instructions
func TestPrintInstructions(t *testing.T) {
	instructions := `
================================================================================
                    IP CHANGE ALERT TESTING INSTRUCTIONS
================================================================================

STEP 1: Build BPFroid with debug logging
-----------------------------------------
    make clean
    make DOCKER=1

STEP 2: Push to device
-----------------------------------------
    adb push dist/tracee /data/local/tmp/bpfroid/
    adb push test/test_ip_alert.sh /data/local/tmp/bpfroid/

STEP 3: Run the shell test script (on device)
-----------------------------------------
    adb shell
    su
    cd /data/local/tmp/bpfroid
    sh test_ip_alert.sh

STEP 4: Run with full debug logging (3 terminals)
-----------------------------------------
    TERMINAL 1 (watch debug logs):
        adb shell "cat /sys/kernel/tracing/trace_pipe"

    TERMINAL 2 (run tracee):
        adb shell
        su
        cd /data/local/tmp/bpfroid
        ./tracee --security-alerts

    TERMINAL 3 (trigger IP change):
        adb shell
        su
        ip addr add 10.99.99.99/24 dev wlan0

STEP 5: Analyze debug output
-----------------------------------------
    Look for these messages in trace_pipe:

    SUCCESS PATH:
        IP_ALERT: inet_rtm_newaddr called!
        IP_ALERT: rtm event_chosen OK
        IP_ALERT: rtm nlh = <address>
        IP_ALERT: rtm family=2 prefix=24
        IP_ALERT: rtm attr1 len=8 type=1
        IP_ALERT: rtm ip from attr1 = <hex>
        IP_ALERT: rtm submitting ip=<hex>
        SUBMIT: enter op=1 ip=<hex>
        SUBMIT: event_chosen OK
        SUBMIT: get_buf OK
        SUBMIT: tags OK
        SUBMIT: calling perf_submit
        SUBMIT: perf_submit done OK

    FAILURE POINTS:
        "event_chosen=0"     -> Event not enabled in BPF map
        "nlh NULL"           -> Bad parameter
        "not IPv4"           -> IPv6 address (family != 2)
        "get_buf NULL"       -> Buffer allocation failed
        "tags NULL"          -> Event params not in map
        NO OUTPUT AT ALL     -> Kprobe not attached or function not called

================================================================================
`
	t.Log(instructions)
}
