package tracee

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aquasecurity/tracee/tracee/external"
)

const (
	bpfroidPeriodicLogDir      = "/data/data/com.example.bpfroidtem/files"
	bpfroidPeriodicLogInterval = 30 * time.Minute
)

type periodicJSONLogger struct {
	dir            string
	rotationWindow time.Duration
	deviceID       string
	mu             sync.Mutex
	closeOnce      sync.Once
	stopCh         chan struct{}
	doneCh         chan struct{}

	activeFile      *os.File
	activeStartTime time.Time
	activeTmpPath   string
}

func newPeriodicJSONLogger(dir string, rotationWindow time.Duration, deviceID string) (*periodicJSONLogger, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory %s: %w", dir, err)
	}

	logger := &periodicJSONLogger{
		dir:            dir,
		rotationWindow: rotationWindow,
		deviceID:       deviceID,
		stopCh:         make(chan struct{}),
		doneCh:         make(chan struct{}),
	}

	if err := logger.openNewFile(time.Now()); err != nil {
		return nil, err
	}

	go logger.rotateLoop()

	return logger, nil
}

func (l *periodicJSONLogger) WriteEvent(event external.Event) error {
	enriched := EnrichedEvent{
		Event:    event,
		DeviceID: l.deviceID,
		WallTime: formatWallTime(event.Timestamp),
	}

	eventBytes, err := json.Marshal(enriched)
	if err != nil {
		return fmt.Errorf("failed to marshal event for periodic json log: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.activeFile == nil {
		if err := l.openNewFile(time.Now()); err != nil {
			return err
		}
	}

	if _, err := l.activeFile.Write(append(eventBytes, '\n')); err != nil {
		return fmt.Errorf("failed to write periodic json log event: %w", err)
	}

	return nil
}

func (l *periodicJSONLogger) Close() error {
	var closeErr error
	l.closeOnce.Do(func() {
		close(l.stopCh)
		<-l.doneCh

		l.mu.Lock()
		defer l.mu.Unlock()
		closeErr = l.closeActiveFile(time.Now())
	})
	return closeErr
}

func (l *periodicJSONLogger) openNewFile(start time.Time) error {
	start = start.Local()
	tmpName := fmt.Sprintf(".bpfroid_%s_current.json.tmp", l.timestampForName(start))
	tmpPath := filepath.Join(l.dir, tmpName)

	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("failed to create periodic json log file %s: %w", tmpPath, err)
	}

	l.activeFile = f
	l.activeStartTime = start
	l.activeTmpPath = tmpPath

	return nil
}

func (l *periodicJSONLogger) rotateLoop() {
	ticker := time.NewTicker(l.rotationWindow)
	defer ticker.Stop()
	defer close(l.doneCh)

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			l.mu.Lock()
			if err := l.closeActiveFile(now); err == nil {
				_ = l.openNewFile(now)
			}
			l.mu.Unlock()
		case <-l.stopCh:
			return
		}
	}
}

func (l *periodicJSONLogger) closeActiveFile(end time.Time) error {
	if l.activeFile == nil {
		return nil
	}

	if end.Before(l.activeStartTime) {
		end = l.activeStartTime
	}

	if err := l.activeFile.Close(); err != nil {
		return fmt.Errorf("failed to close periodic json log file %s: %w", l.activeTmpPath, err)
	}

	finalName := fmt.Sprintf(
		"bpfroid_%s_to_%s.json",
		l.startDateTimeForName(l.activeStartTime),
		l.endTimeForName(end.Local()),
	)
	finalPath := filepath.Join(l.dir, finalName)
	for i := 1; ; i++ {
		if _, err := os.Stat(finalPath); os.IsNotExist(err) {
			break
		}
		finalName = fmt.Sprintf(
			"bpfroid_%s_to_%s_%d.json",
			l.startDateTimeForName(l.activeStartTime),
			l.endTimeForName(end.Local()),
			i,
		)
		finalPath = filepath.Join(l.dir, finalName)
	}

	if err := os.Rename(l.activeTmpPath, finalPath); err != nil {
		return fmt.Errorf("failed to finalize periodic json log file %s: %w", finalPath, err)
	}

	l.activeFile = nil
	l.activeTmpPath = ""

	return nil
}

func (l *periodicJSONLogger) timestampForName(ts time.Time) string {
	return ts.Format("20060102_150405")
}

func (l *periodicJSONLogger) startDateTimeForName(ts time.Time) string {
	return ts.Format("2006-01-02_15-04-05")
}

func (l *periodicJSONLogger) endTimeForName(ts time.Time) string {
	return ts.Format("15-04-05")
}
