package tracee

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/tracee/external"
)

const (
	rtsEnabledEnv         = "BPFROID_RTS_ENABLED"
	rtsActionEnv          = "BPFROID_RTS_BROADCAST_ACTION"
	rtsReceiverPackageEnv = "BPFROID_RTS_RECEIVER_PACKAGE"
	rtsDefaultAction      = "com.example.bpfroidtem.RTS_ALERT"
)

type rtsForwarder struct {
	enabled         bool
	broadcastAction string
	receiverPackage string
}

func newRTSForwarderFromEnv() *rtsForwarder {
	enabled := parseBoolEnv(rtsEnabledEnv)
	if !enabled {
		return nil
	}

	action := strings.TrimSpace(os.Getenv(rtsActionEnv))
	if action == "" {
		action = rtsDefaultAction
	}

	return &rtsForwarder{
		enabled:         true,
		broadcastAction: action,
		receiverPackage: strings.TrimSpace(os.Getenv(rtsReceiverPackageEnv)),
	}
}

func (r *rtsForwarder) Close() error {
	return nil
}

func (r *rtsForwarder) Forward(event external.Event) error {
	if r == nil || !r.enabled || !isSecurityAlertEvent(int32(event.EventID)) {
		return nil
	}

	alertType := mapAlertType(int32(event.EventID), event.EventName)
	argsJSON, err := json.Marshal(event.Args)
	if err != nil {
		return fmt.Errorf("failed to marshal event args for RTS broadcast: %w", err)
	}

	cmdArgs := []string{
		"broadcast",
		"-a", r.broadcastAction,
		"--es", "alert_type", alertType,
		"--es", "event_name", event.EventName,
		"--es", "process_name", event.ProcessName,
		"--ei", "pid", strconv.Itoa(event.ProcessID),
		"--ei", "uid", strconv.Itoa(event.UserID),
		"--es", "args_json", string(argsJSON),
	}

	if r.receiverPackage != "" {
		cmdArgs = append(cmdArgs, "-p", r.receiverPackage)
	}

	output, err := exec.Command("am", cmdArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("rts broadcast failed: %w (output: %s)", err, strings.TrimSpace(string(output)))
	}

	return nil
}

func parseBoolEnv(key string) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if value == "" {
		return false
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false
	}
	return parsed
}

func isSecurityAlertEvent(eventID int32) bool {
	switch eventID {
	case MemProtAlertEventID,
		UidChangedAlertEventID,
		WriteAlertEventID,
		IPChangedAlertEventID,
		SELinuxModeChangeAlertEventID,
		SELinuxPolicyReloadAlertEventID,
		SELinuxProtectedResourceAccessAlertEventID,
		SELinuxDenialEventID,
		SELinuxRepeatedDenialAlertEventID,
		SuSudoAlertEventID:
		return true
	default:
		return false
	}
}

func mapAlertType(eventID int32, fallbackEventName string) string {
	switch eventID {
	case MemProtAlertEventID:
		return "MEM_PROT_ALERT"
	case UidChangedAlertEventID:
		return "UID_CHANGED_ALERT"
	case WriteAlertEventID:
		return "WRITE_ALERT"
	case IPChangedAlertEventID:
		return "IP_CHANGED_ALERT"
	case SELinuxModeChangeAlertEventID:
		return "SELINUX_MODE_CHANGE_ALERT"
	case SELinuxPolicyReloadAlertEventID:
		return "SELINUX_POLICY_RELOAD_ALERT"
	case SELinuxProtectedResourceAccessAlertEventID:
		return "SELINUX_PROTECTED_RESOURCE_ACCESS_ALERT"
	case SELinuxDenialEventID:
		return "SELINUX_DENIAL_ALERT"
	case SELinuxRepeatedDenialAlertEventID:
		return "SELINUX_REPEATED_DENIAL_ALERT"
	case SuSudoAlertEventID:
		return "SU_SUDO_ALERT"
	default:
		return strings.ToUpper(fallbackEventName)
	}
}
