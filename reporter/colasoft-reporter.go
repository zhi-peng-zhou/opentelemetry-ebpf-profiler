package reporter

import (
	"context"
	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"
	"github.com/toliu/opentelemetry-ebpf-profiler/libpf"
	"github.com/toliu/opentelemetry-ebpf-profiler/libpf/xsync"
	"github.com/toliu/opentelemetry-ebpf-profiler/reporter/colasoft"
	"github.com/toliu/opentelemetry-ebpf-profiler/times"
	"github.com/toliu/opentelemetry-ebpf-profiler/util"
	"time"
)

type (
	ColaSoft struct {
		*OTLPReporter

		writer     colasoft.Writer
		addr2liner colasoft.Addr2liner
	}

	ColaSoftConfig struct {
		Frequency, PresentCores int
		ReportInterval          time.Duration
		Intervals               *times.Times
	}

	openerConvert ExecutableOpener
)

var _ Reporter = (*ColaSoft)(nil)

func (o openerConvert) Convert() (colasoft.ReadAtCloser, error) { return o() }

func ColaSoftReporter(ctx context.Context, cfg *ColaSoftConfig) (*ColaSoft, error) {
	cacheSize := cfg.CacheSize()
	otlp := &OTLPReporter{
		samplesPerSecond: cfg.Frequency,
		stopSignal:       make(chan libpf.Void),
		traceEvents:      xsync.NewRWMutex(map[traceAndMetaKey]*traceFramesCounts{}),
	}
	var err error
	if otlp.fallbackSymbols, err = lru.NewSynced[libpf.FrameID, string](cacheSize, libpf.FrameID.Hash32); err != nil {
		return nil, err
	} else if otlp.executables, err = lru.NewSynced[libpf.FileID, execInfo](cacheSize, libpf.FileID.Hash32); err != nil {
		return nil, err
	} else if otlp.frames, err = lru.NewSynced[libpf.FileID, *xsync.RWMutex[map[libpf.AddressOrLineno]sourceInfo]](cacheSize, libpf.FileID.Hash32); err != nil {
		return nil, err
	} else if otlp.cgroupv2ID, err = lru.NewSynced[util.PID, string](cacheSize, func(pid util.PID) uint32 { return uint32(pid) }); err != nil {
		return nil, err
	} else if otlp.hostmetadata, err = lru.NewSynced[string, string](115, hashString); err != nil {
		return nil, err
	}
	otlp.cgroupv2ID.SetLifetime(90 * time.Second)

	reporter := &ColaSoft{OTLPReporter: otlp}
	var cancelReporting context.CancelFunc
	ctx, cancelReporting = context.WithCancel(ctx)
	go func() {
		tick := time.NewTicker(cfg.ReportInterval)
		defer tick.Stop()
		defer cancelReporting()
		for {
			select {
			case <-ctx.Done():
				return
			case <-otlp.stopSignal:
				return
			case <-tick.C:
				if err = reporter.report(ctx); err != nil {
					log.Errorf("Request failed: %v", err)
				}
				tick.Reset(libpf.AddJitter(cfg.ReportInterval, 0.2))
			}
		}
	}()

	return reporter, nil
}

func (c *ColaSoft) Stop()                   { c.OTLPReporter.Stop() }
func (c *ColaSoft) GetMetrics() (m Metrics) { return }
func (c *ColaSoft) ExecutableMetadata(fd libpf.FileID, filename, buildID string, it libpf.InterpreterType, eopener ExecutableOpener) {
	if c.addr2liner != nil && eopener != nil {
		c.addr2liner.PrepareFile(filename, fd.Base64(), openerConvert(eopener).Convert)
	}
	c.OTLPReporter.ExecutableMetadata(fd, filename, buildID, it, eopener)
}

func (c *ColaSoft) SetWriter(w colasoft.Writer)                  { c.writer = w }
func (c *ColaSoft) SetAddr2liner(addr2liner colasoft.Addr2liner) { c.addr2liner = addr2liner }

func (c *ColaSoft) report(ctx context.Context) error {
	protocol, _, _ := c.OTLPReporter.getProfile()
	if c.writer == nil {
		return nil
	}
	return c.writer.WriteProfile(ctx, protocol)
}

func (c *ColaSoftConfig) CacheSize() uint32 {
	const (
		traceCacheIntervals = 6
		traceCacheMinSize   = 65536
	)
	maxElements := uint32(uint16(c.Frequency) * uint16(c.Intervals.MonitorInterval().Seconds()) * uint16(c.PresentCores))
	size := maxElements * uint32(traceCacheIntervals)
	if size < traceCacheMinSize {
		size = traceCacheMinSize
	}
	return util.NextPowerOfTwo(size)
}
