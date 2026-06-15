package tracee

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"sync"

	"github.com/aquasecurity/tracee/tracee/external"
)

func (t *Tracee) runEventPipeline(done <-chan struct{}) error {
	var errcList []<-chan error

	// Source pipeline stage.
	rawEventChan, errc, err := t.decodeRawEvent(done)
	if err != nil {
		return err
	}
	errcList = append(errcList, errc)

	processedEventChan, errc, err := t.processRawEvent(done, rawEventChan)
	if err != nil {
		return err
	}
	errcList = append(errcList, errc)

	printEventChan, errc, err := t.prepareEventForPrint(done, processedEventChan)
	if err != nil {
		return err
	}
	errcList = append(errcList, errc)

	errc, err = t.printEvent(done, printEventChan)
	if err != nil {
		return err
	}
	errcList = append(errcList, errc)

	// Pipeline started. Waiting for pipeline to complete
	return t.WaitForPipeline(errcList...)
}

type RawEvent struct {
	Ctx      context
	RawArgs  map[argTag]interface{}
	ArgsTags []argTag
}

func (t *Tracee) decodeRawEvent(done <-chan struct{}) (<-chan RawEvent, <-chan error, error) {
	out := make(chan RawEvent)
	errc := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errc)
		for dataRaw := range t.eventsChannel {
			dataBuff := bytes.NewBuffer(dataRaw)
			var ctx context
			err := binary.Read(dataBuff, binary.LittleEndian, &ctx)
			if err != nil {
				errc <- err
				continue
			}

			rawArgs := make(map[argTag]interface{})
			argsTags := make([]argTag, ctx.Argnum)
			for i := 0; i < int(ctx.Argnum); i++ {
				tag, val, err := readArgFromBuff(dataBuff)
				if err != nil {
					errc <- err
					continue
				}
				argsTags[i] = tag
				if ctx.EventID == GenericUprobeEventID || ctx.EventID == GenericApiUprobeEventID {
					rawArgs[argTag(i)] = val
				} else {
					rawArgs[tag] = val
				}
			}
			select {
			case out <- RawEvent{ctx, rawArgs, argsTags}:
			case <-done:
				return
			}
		}
	}()
	return out, errc, nil
}

func (t *Tracee) processRawEvent(done <-chan struct{}, in <-chan RawEvent) (<-chan RawEvent, <-chan error, error) {
	out := make(chan RawEvent)
	errc := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errc)
		for rawEvent := range in {
			if !t.shouldProcessEvent(rawEvent) {
				continue
			}
			err := t.processEvent(&rawEvent.Ctx, rawEvent.RawArgs)
			if err != nil {
				errc <- err
				continue
			}
			select {
			case out <- rawEvent:
			case <-done:
				return
			}
		}
	}()
	return out, errc, nil
}

func (t *Tracee) getStackAddresses(StackID uint32) ([]uint64, error) {
	StackAddresses := make([]uint64, maxStackDepth)
	stackFrameSize := (strconv.IntSize / 8)

	// Lookup the StackID in the map
	// The ID could have aged out of the Map, as it only holds a finite number of
	// Stack IDs in it's Map
	stackBytes, err := t.StackAddressesMap.GetValue(StackID, stackFrameSize*maxStackDepth)
	if err != nil {
		return StackAddresses[0:0], nil
	}

	stackCounter := 0
	for i := 0; i < len(stackBytes); i += stackFrameSize {
		StackAddresses[stackCounter] = 0
		stackAddr := binary.LittleEndian.Uint64(stackBytes[i : i+stackFrameSize])
		if stackAddr == 0 {
			break
		}
		StackAddresses[stackCounter] = stackAddr
		stackCounter++
	}

	// Attempt to remove the ID from the map so we don't fill it up
	// But if this fails continue on
	_ = t.StackAddressesMap.DeleteKey(StackID)

	return StackAddresses[0:stackCounter], nil
}

func (t *Tracee) prepareEventForPrint(done <-chan struct{}, in <-chan RawEvent) (<-chan external.Event, <-chan error, error) {
	out := make(chan external.Event, 1000)
	errc := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errc)
		for rawEvent := range in {
			if !t.shouldPrintEvent(rawEvent) {
				continue
			}
			err := t.prepareArgsForPrint(&rawEvent.Ctx, rawEvent.RawArgs)
			if err != nil {
				errc <- err
				continue
			}
			args := make([]interface{}, rawEvent.Ctx.Argnum)
			argMetas := make([]external.ArgMeta, rawEvent.Ctx.Argnum)
			if rawEvent.Ctx.EventID == GenericUprobeEventID || rawEvent.Ctx.EventID == GenericApiUprobeEventID {
				for i, _ := range rawEvent.ArgsTags {
					args[i] = rawEvent.RawArgs[argTag(i)]
					if i == 0 {
						argMetas[i] = external.ArgMeta{Type: "char*", Name: "fn"}
						continue
					}
					argMetas[i] = external.ArgMeta{Type: "char*", Name: fmt.Sprintf("arg%d", i)}
				}
			} else {
				for i, tag := range rawEvent.ArgsTags {
					args[i] = rawEvent.RawArgs[tag]
					argMeta, ok := t.DecParamName[rawEvent.Ctx.EventID%2][tag]
					if ok {
						argMetas[i] = argMeta
					} else {
						errc <- fmt.Errorf("Invalid arg tag for event %d\n", rawEvent.Ctx.EventID)
						continue
					}
				}
			}

			// Add stack trace if needed
			var StackAddresses []uint64
			if t.config.Output.StackAddresses {
				StackAddresses, _ = t.getStackAddresses(rawEvent.Ctx.StackID)
			}

			evt, err := newEvent(rawEvent.Ctx, argMetas, args, StackAddresses)
			if err != nil {
				errc <- err
				continue
			}

			// Check for SELinux denial events and track for repeated denial alerts
			// Tracks both SELinuxProtectedResourceAccessAlertEventID (high-level) and
			// SELinuxDenialEventID (low-level kernel security_inode_permission denials)
			if t.selinuxDenialTracker != nil {
				var repeatedAlert *external.Event
				if rawEvent.Ctx.EventID == SELinuxProtectedResourceAccessAlertEventID {
					repeatedAlert = t.checkAndRecordSELinuxDenial(&rawEvent, &evt)
				} else if rawEvent.Ctx.EventID == SELinuxDenialEventID {
					repeatedAlert = t.checkAndRecordSELinuxInodeDenial(&rawEvent, &evt)
				}
				if repeatedAlert != nil {
					// Emit the repeated denial alert first
					select {
					case out <- *repeatedAlert:
					case <-done:
						return
					}
				}
			}

			select {
			case out <- evt:
			case <-done:
				return
			}
		}
	}()
	return out, errc, nil
}

// checkAndRecordSELinuxDenial checks if a SELinux protected resource access event is a denial,
// records it in the denial tracker, and returns a repeated denial alert event if threshold is reached
func (t *Tracee) checkAndRecordSELinuxDenial(rawEvent *RawEvent, evt *external.Event) *external.Event {
	// Extract the result field to check if this is a denial
	// The result field is the 7th argument (index 6) based on EventsIDToParams
	// result: 0=DENIED, 1=ALLOWED
	resultArg := evt.Args[6]
	resultStr, ok := resultArg.Value.(string)
	if !ok {
		return nil
	}
	
	// Only track denials (result contains "DENIED")
	if resultStr != "DENIED" {
		return nil
	}

	// Extract pathname (index 1) and access_type (index 3)
	pathname := ""
	if pathArg := evt.Args[1]; pathArg.Value != nil {
		if pathStr, ok := pathArg.Value.(string); ok {
			pathname = pathStr
		}
	}

	accessType := ""
	if accessArg := evt.Args[3]; accessArg.Value != nil {
		if accessStr, ok := accessArg.Value.(string); ok {
			accessType = accessStr
		}
	}

	// Create the denial key for tracking
	// Truncate pathname to prefix for grouping similar denials
	pathPrefix := pathname
	if len(pathPrefix) > 50 {
		pathPrefix = pathPrefix[:50]
	}

	key := SELinuxDenialKey{
		PID:         evt.ProcessID,
		UID:         uint32(evt.UserID),
		ProcessName: evt.ProcessName,
		Operation:   accessType,
		PathPrefix:  pathPrefix,
	}

	// Record the denial and check if we should alert
	shouldAlert, count, firstTs, lastTs, cooldownActive := t.selinuxDenialTracker.RecordDenial(
		key,
		uint64(evt.Timestamp*1000000), // convert to microseconds
		pathname,
		accessType,
	)

	if !shouldAlert {
		return nil
	}

	// Create a synthetic repeated denial alert event
	return t.createRepeatedDenialAlertEvent(evt, count, firstTs, lastTs, cooldownActive)
}

// createRepeatedDenialAlertEvent creates a synthetic event for the repeated denial alert
func (t *Tracee) createRepeatedDenialAlertEvent(originalEvt *external.Event, denialCount uint32, firstTs uint64, lastTs uint64, cooldownActive bool) *external.Event {
	// Get params from EventsIDToParams for SELinuxRepeatedDenialAlertEventID
	params := EventsIDToParams[SELinuxRepeatedDenialAlertEventID]

	// Build the args
	args := make([]external.Argument, len(params))
	for i, param := range params {
		args[i] = external.Argument{
			ArgMeta: param,
		}
	}

	// Populate the argument values
	// {Type: "const char*", Name: "process_name"}
	args[0].Value = originalEvt.ProcessName
	// {Type: "int", Name: "pid"}
	args[1].Value = int32(originalEvt.ProcessID)
	// {Type: "int", Name: "tgid"}
	args[2].Value = int32(originalEvt.ProcessID) // TGID equals PID for the main thread
	// {Type: "unsigned int", Name: "uid"}
	args[3].Value = uint32(originalEvt.UserID)
	// {Type: "const char*", Name: "last_denied_path"}
	if len(originalEvt.Args) > 1 {
		if pathStr, ok := originalEvt.Args[1].Value.(string); ok {
			args[4].Value = pathStr
		} else {
			args[4].Value = ""
		}
	}
	// {Type: "const char*", Name: "last_operation"}
	if len(originalEvt.Args) > 3 {
		if opStr, ok := originalEvt.Args[3].Value.(string); ok {
			args[5].Value = opStr
		} else {
			args[5].Value = ""
		}
	}
	// {Type: "unsigned int", Name: "denial_count"}
	args[6].Value = FormatSELinuxRepeatedDenialSummary(denialCount, t.selinuxDenialTracker.GetTimeWindowSecs())
	// {Type: "unsigned int", Name: "time_window_secs"}
	args[7].Value = t.selinuxDenialTracker.GetTimeWindowSecs()
	// {Type: "unsigned int", Name: "threshold"}
	args[8].Value = t.selinuxDenialTracker.GetThreshold()
	// {Type: "unsigned long", Name: "first_denial_ts"}
	args[9].Value = firstTs
	// {Type: "unsigned long", Name: "last_denial_ts"}
	args[10].Value = lastTs
	// {Type: "const char*", Name: "cooldown_state"}
	args[11].Value = PrintSELinuxRepeatedDenialCooldownState(cooldownActive)

	// Create the event
	alertEvt := &external.Event{
		Timestamp:           originalEvt.Timestamp,
		ProcessID:           originalEvt.ProcessID,
		ThreadID:            originalEvt.ThreadID,
		ParentProcessID:     originalEvt.ParentProcessID,
		HostProcessID:       originalEvt.HostProcessID,
		HostThreadID:        originalEvt.HostThreadID,
		HostParentProcessID: originalEvt.HostParentProcessID,
		UserID:              originalEvt.UserID,
		MountNS:             originalEvt.MountNS,
		PIDNS:               originalEvt.PIDNS,
		ProcessName:         originalEvt.ProcessName,
		HostName:            originalEvt.HostName,
		EventID:             int(SELinuxRepeatedDenialAlertEventID),
		EventName:           EventsIDToEvent[SELinuxRepeatedDenialAlertEventID].Name,
		ArgsNum:             len(args),
		ReturnValue:         0,
		Args:                args,
		StackAddresses:      nil,
	}

	return alertEvt
}

// checkAndRecordSELinuxInodeDenial handles SELinuxDenialEventID events from security_inode_permission kprobe
// These are low-level kernel permission denials (always denied, no result field to check)
func (t *Tracee) checkAndRecordSELinuxInodeDenial(rawEvent *RawEvent, evt *external.Event) *external.Event {
	// Extract pathname (index 0) from SELinuxDenialEventID event
	pathname := ""
	if len(evt.Args) > 0 && evt.Args[0].Value != nil {
		if pathStr, ok := evt.Args[0].Value.(string); ok {
			pathname = pathStr
		}
	}

	// Extract mask (index 1) to determine operation type
	operation := "permission_check"
	if len(evt.Args) > 1 && evt.Args[1].Value != nil {
		// mask is already formatted by PrintSELinuxPermissionMask
		if maskStr, ok := evt.Args[1].Value.(string); ok {
			operation = maskStr
		}
	}

	// Create the denial key for tracking
	// Truncate pathname to prefix for grouping similar denials
	pathPrefix := pathname
	if len(pathPrefix) > 50 {
		pathPrefix = pathPrefix[:50]
	}

	key := SELinuxDenialKey{
		PID:         evt.ProcessID,
		UID:         uint32(evt.UserID),
		ProcessName: evt.ProcessName,
		Operation:   operation,
		PathPrefix:  pathPrefix,
	}

	// Record the denial and check if we should alert
	shouldAlert, count, firstTs, lastTs, cooldownActive := t.selinuxDenialTracker.RecordDenial(
		key,
		uint64(evt.Timestamp*1000000), // convert to microseconds
		pathname,
		operation,
	)

	if !shouldAlert {
		return nil
	}

	// Create a synthetic repeated denial alert event
	return t.createRepeatedDenialAlertEvent(evt, count, firstTs, lastTs, cooldownActive)
}

func (t *Tracee) printEvent(done <-chan struct{}, in <-chan external.Event) (<-chan error, error) {
	errc := make(chan error, 1)
	go func() {
		defer close(errc)
		for printEvent := range in {
			t.stats.eventCounter.Increment()
			t.printer.Print(printEvent)
		}
	}()
	return errc, nil
}

// WaitForPipeline waits for results from all error channels.
func (t *Tracee) WaitForPipeline(errs ...<-chan error) error {
	errc := MergeErrors(errs...)
	for err := range errc {
		t.handleError(err)
	}
	return nil
}

// MergeErrors merges multiple channels of errors.
// Based on https://blog.golang.org/pipelines.
func MergeErrors(cs ...<-chan error) <-chan error {
	var wg sync.WaitGroup
	// We must ensure that the output channel has the capacity to hold as many errors
	// as there are error channels. This will ensure that it never blocks, even
	// if WaitForPipeline returns early.
	out := make(chan error, len(cs))

	// Start an output goroutine for each input channel in cs.  output
	// copies values from c to out until c is closed, then calls wg.Done.
	output := func(c <-chan error) {
		for n := range c {
			out <- n
		}
		wg.Done()
	}
	wg.Add(len(cs))
	for _, c := range cs {
		go output(c)
	}

	// Start a goroutine to close out once all the output goroutines are
	// done.  This must start after the wg.Add call.
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}
