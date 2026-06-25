package tracee

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/template"
	"time"
	_ "time/tzdata"

	"github.com/aquasecurity/tracee/tracee/external"
)

type eventPrinter interface {
	// Init serves as the initializer method for every event Printer type
	Init() error
	// Preamble prints something before event printing begins (one time)
	Preamble()
	// Epilogue prints something after event printing ends (one time)
	Epilogue(stats statsStore)
	// Print prints a single event
	Print(event external.Event)
	// Error prints a single error
	Error(err error)
	// dispose of resources
	Close()
}

var eotEvent external.Event = external.Event{EventName: string(rune(4))}
var deviceID string

func SetDeviceID(id string) {
	deviceID = id
}

var bootTime time.Time

func initBootTime() {
	f, err := os.Open("/proc/stat")
	if err != nil {
		bootTime = time.Now()
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "btime ") {
			parts := strings.Fields(line)
			if len(parts) == 2 {
				sec, err := strconv.ParseInt(parts[1], 10, 64)
				if err == nil {
					bootTime = time.Unix(sec, 0)
					return
				}
			}
		}
	}

	bootTime = time.Now()
}

var deviceLocation *time.Location

func initDeviceLocation() {
	out, err := exec.Command("getprop", "persist.sys.timezone").Output()
	if err == nil {
		tzName := strings.TrimSpace(string(out))

		if tzName != "" {
			loc, err := time.LoadLocation(tzName)
			if err == nil {
				deviceLocation = loc
				return
			}
		}
	}

	// fallback: check TZ environment variable
	if tzEnv := os.Getenv("TZ"); tzEnv != "" {
		loc, err := time.LoadLocation(tzEnv)
		if err == nil {
			deviceLocation = loc
			return
		}
	}

	deviceLocation = time.Local
}

func newEventPrinter(kind string, containerMode bool, eot bool, out io.WriteCloser, err io.WriteCloser) (eventPrinter, error) {
	if bootTime.IsZero() {
		initBootTime()
		initDeviceLocation()
	}
	var res eventPrinter
	var initError error
	switch {
	case kind == "table":
		res = &tableEventPrinter{
			out:           out,
			err:           err,
			verbose:       false,
			containerMode: containerMode,
			deviceID:      deviceID,
		}
	case kind == "table-verbose":
		res = &tableEventPrinter{
			out:           out,
			err:           err,
			verbose:       true,
			containerMode: containerMode,
			deviceID:      deviceID,
		}
	case kind == "json":
		res = &jsonEventPrinter{
			eot: eot,
			out: out,
			err: err,
			deviceID:      deviceID,
		}
	case kind == "gob":
		res = &gobEventPrinter{
			eot: eot,
			out: out,
			err: err,
		}
	case strings.HasPrefix(kind, "gotemplate="):
		res = &templateEventPrinter{
			eot:           eot,
			out:           out,
			err:           err,
			containerMode: containerMode,
			templatePath:  strings.Split(kind, "=")[1],
		}
	}
	initError = res.Init()
	if initError != nil {
		return nil, initError
	}
	return res, nil
}

func newEvent(ctx context, argMetas []external.ArgMeta, args []interface{}, StackAddresses []uint64) (external.Event, error) {
	e := external.Event{
		Timestamp:           float64(ctx.Ts) / 1000000.0,
		ProcessID:           int(ctx.Pid),
		ThreadID:            int(ctx.Tid),
		ParentProcessID:     int(ctx.Ppid),
		HostProcessID:       int(ctx.HostPid),
		HostThreadID:        int(ctx.HostTid),
		HostParentProcessID: int(ctx.HostPpid),
		UserID:              int(ctx.Uid),
		MountNS:             int(ctx.MntID),
		PIDNS:               int(ctx.PidID),
		ProcessName:         string(bytes.TrimRight(ctx.Comm[:], "\x00")),
		HostName:            string(bytes.TrimRight(ctx.UtsName[:], "\x00")),
		EventID:             int(ctx.EventID),
		EventName:           EventsIDToEvent[int32(ctx.EventID)].Name,
		ArgsNum:             int(ctx.Argnum),
		ReturnValue:         int(ctx.Retval),
		Args:                make([]external.Argument, 0, len(args)),
		StackAddresses:      StackAddresses,
	}
	for i, arg := range args {
		e.Args = append(e.Args, external.Argument{
			ArgMeta: argMetas[i],
			Value:   arg,
		})
	}
	return e, nil
}

type tableEventPrinter struct {
	tracee        *Tracee
	out           io.WriteCloser
	err           io.WriteCloser
	verbose       bool
	containerMode bool
	deviceID      string
}

func (p tableEventPrinter) Init() error { return nil }

func (p tableEventPrinter) Preamble() {
	if p.verbose {
		if p.containerMode {
			fmt.Fprintf(p.out, "%-18s %-24s %-16s %-12s %-12s %-6s %-16s %-15s %-15s %-15s %-16s %-20s %s",  "DEVICE_ID", "TIMESTAMP", "UTS_NAME", "MNT_NS", "PID_NS", "UID", "COMM", "PID/host", "TID/host", "PPID/host", "RET", "EVENT", "ARGS")
		} else {
			fmt.Fprintf(p.out, "%-18s %-24s %-16s %-12s %-12s %-6s %-16s %-7s %-7s %-7s %-16s %-20s %s",  "DEVICE_ID", "TIMESTAMP", "UTS_NAME", "MNT_NS", "PID_NS", "UID", "COMM", "PID", "TID", "PPID", "RET", "EVENT", "ARGS")
		}
	} else {
		if p.containerMode {
			fmt.Fprintf(p.out, "%-18s %-24s %-16s %-6s %-16s %-15s %-15s %-16s %-20s %s",  "DEVICE_ID", "TIMESTAMP", "UTS_NAME", "UID", "COMM", "PID/host", "TID/host", "RET", "EVENT", "ARGS")
		} else {
			fmt.Fprintf(p.out, "%-18s %-24s %-6s %-16s %-7s %-7s %-16s %-20s %s",  "DEVICE_ID", "TIMESTAMP", "UID", "COMM", "PID", "TID", "RET", "EVENT", "ARGS")
		}
	}
	fmt.Fprintln(p.out)
}

func (p tableEventPrinter) Print(event external.Event) {
	formattedTime := formatWallTime(event.Timestamp)
	if p.verbose {
		if p.containerMode {
			fmt.Fprintf(p.out, "%-18s %-24s %-16s %-12d %-12d %-6d %-16s %-7d/%-7d %-7d/%-7d %-7d/%-7d %-16d %-20s ",p.deviceID, formattedTime, event.HostName, event.MountNS, event.PIDNS, event.UserID, event.ProcessName, event.ProcessID, event.HostProcessID, event.ThreadID, event.HostThreadID, event.ParentProcessID, event.ParentProcessID, event.ReturnValue, event.EventName)
		} else {
			fmt.Fprintf(p.out, "%-18s %-24s %-16s %-12d %-12d %-6d %-16s %-7d %-7d %-7d %-16d %-20s ", p.deviceID, formattedTime, event.HostName, event.MountNS, event.PIDNS, event.UserID, event.ProcessName, event.ProcessID, event.ThreadID, event.ParentProcessID, event.ReturnValue, event.EventName)
		}
	} else {
		if p.containerMode {
			fmt.Fprintf(p.out, "%-18s %-24s %-16s %-6d %-16s %-7d/%-7d %-7d/%-7d %-16d %-20s ", p.deviceID, formattedTime, event.HostName, event.UserID, event.ProcessName, event.ProcessID, event.HostProcessID, event.ThreadID, event.HostThreadID, event.ReturnValue, event.EventName)
		} else {
			fmt.Fprintf(p.out, "%-18s %-24s %-6d %-16s %-7d %-7d %-16d %-20s ",p.deviceID,  formattedTime, event.UserID, event.ProcessName, event.ProcessID, event.ThreadID, event.ReturnValue, event.EventName)
		}
	}
	for i, arg := range event.Args {
		if i == 0 {
			fmt.Fprintf(p.out, "%s: %v", arg.Name, arg.Value)
		} else {
			fmt.Fprintf(p.out, ", %s: %v", arg.Name, arg.Value)
		}
	}
	fmt.Fprintln(p.out)
}

func (p tableEventPrinter) Error(err error) {
	fmt.Fprintf(p.err, "%v\n", err)
}

func (p tableEventPrinter) Epilogue(stats statsStore) {
	fmt.Println()
	fmt.Fprintf(p.out, "End of events stream\n")
	fmt.Fprintf(p.out, "Stats: %+v\n", stats)
}

func (p tableEventPrinter) Close() {
	p.out.Close()
	p.err.Close()
}

type templateEventPrinter struct {
	tracee        *Tracee
	out           io.WriteCloser
	err           io.WriteCloser
	containerMode bool
	templatePath  string
	templateObj   **template.Template
	eot           bool
}

func (p *templateEventPrinter) Init() error {
	tmplPath := p.templatePath
	if tmplPath != "" {
		tmpl, err := template.ParseFiles(tmplPath)
		if err != nil {
			return err
		}
		p.templateObj = &tmpl
	} else {
		return errors.New("Please specify a gotemplate for event-based output")
	}
	return nil
}

func (p templateEventPrinter) Preamble() {}

func (p templateEventPrinter) Error(err error) {
	fmt.Fprintf(p.err, "%v", err)
}

type EnrichedEvent struct {
	external.Event
	DeviceID string `json:"deviceId"`
	WallTime   string `json:"wallTime"`	
}

func (p templateEventPrinter) Print(event external.Event) {
	
	if p.templateObj != nil {
		err := (*p.templateObj).Execute(p.out, event)
		if err != nil {
			p.Error(err)
		}
	} else {
		fmt.Fprintf(p.out, "Template Obj is nil")
	}
}


func (p templateEventPrinter) Epilogue(stats statsStore) {
	if p.eot {
		p.Print(eotEvent)
	}
}

func (p templateEventPrinter) Close() {
	p.out.Close()
	p.err.Close()
}

type jsonEventPrinter struct {
	out io.WriteCloser
	err io.WriteCloser
	eot bool
	deviceID string
}

func (p jsonEventPrinter) Init() error { return nil }

func (p jsonEventPrinter) Preamble() {}

func (p jsonEventPrinter) Print(event external.Event) {
	enriched := EnrichedEvent{
		Event:    event,
		DeviceID: p.deviceID,
		WallTime: formatWallTime(event.Timestamp),
	}
	eBytes, err := json.Marshal(enriched)
	if err != nil {
		p.Error(err)
		return
	}
	fmt.Fprintln(p.out, string(eBytes))
}

// func (p jsonEventPrinter) Print(event external.Event) {
// 	eBytes, err := json.Marshal(event)
// 	if err != nil {
// 		p.Error(err)
// 	}
// 	fmt.Fprintln(p.out, string(eBytes))
// }

func (p jsonEventPrinter) Error(e error) {
	eBytes, err := json.Marshal(e)
	if err != nil {
		return
	}
	fmt.Fprintln(p.err, string(eBytes))
}

func (p jsonEventPrinter) Epilogue(stats statsStore) {
	if p.eot {
		p.Print(eotEvent)
	}
}

func (p jsonEventPrinter) Close() {
	p.out.Close()
	p.err.Close()
}

// gobEventPrinter is printing events using golang's builtin Gob serializer
// an additional event is added at the end to signal end of transmission
// this event can be identified by it's "EventName" which will be the ASCII "End Of Transmission" character
type gobEventPrinter struct {
	out    io.WriteCloser
	err    io.WriteCloser
	outEnc *gob.Encoder
	errEnc *gob.Encoder
	eot    bool
}

func (p *gobEventPrinter) Init() error {
	p.outEnc = gob.NewEncoder(p.out)
	p.errEnc = gob.NewEncoder(p.err)
	return nil
}

func (p *gobEventPrinter) Preamble() {}

func (p *gobEventPrinter) Print(event external.Event) {
	err := p.outEnc.Encode(event)
	if err != nil {
		p.Error(err)
	}
}

func (p *gobEventPrinter) Error(e error) {
	_ = p.errEnc.Encode(e)
}

func (p *gobEventPrinter) Epilogue(stats statsStore) {
	if p.eot {
		p.Print(eotEvent)
	}
}

func (p gobEventPrinter) Close() {
	p.out.Close()
	p.err.Close()
}

func formatWallTime(tsSinceBoot float64) string {
	sec := int64(tsSinceBoot)
	nsec := int64((tsSinceBoot - float64(sec)) * 1e9)
	return bootTime.In(deviceLocation).Add(time.Duration(sec)*time.Second + time.Duration(nsec)).Format("2006-01-02 15:04:05.000")
}