package main

import (
	"context"
	"encoding/json"
	cebpf "github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
	"github.com/tklauser/numcpus"
	"github.com/toliu/opentelemetry-ebpf-profiler/host"
	"github.com/toliu/opentelemetry-ebpf-profiler/reporter"
	"github.com/toliu/opentelemetry-ebpf-profiler/reporter/colasoft"
	"github.com/toliu/opentelemetry-ebpf-profiler/times"
	"github.com/toliu/opentelemetry-ebpf-profiler/tracehandler"
	"github.com/toliu/opentelemetry-ebpf-profiler/tracer"
	tracertypes "github.com/toliu/opentelemetry-ebpf-profiler/tracer/types"
	"go.opentelemetry.io/proto/otlp/profiles/v1experimental"
	"golang.org/x/sys/unix"
	"os"
	"os/signal"
	"time"
)

type (
	Writer struct {
		output string
	}

	Addr2liners struct{}
)

var (
	_ colasoft.Writer     = (*Writer)(nil)
	_ colasoft.Addr2liner = (*Addr2liners)(nil)
)

func (w *Writer) WriteProfile(_ context.Context, pprof *v1experimental.Profile) error {
	content, err := json.MarshalIndent(pprof, "", "  ")
	if err != nil {
		return err
	}
	log.Infof("write file %s", w.output)
	return os.WriteFile(w.output, content, os.ModePerm)
}

func (a *Addr2liners) PrepareFile(filename string, fd string, opener colasoft.Opener) {
	log.Infof("\tprepare file %s, %s", filename, fd)
}

func main() {
	// Context to drive main goroutine and the Tracer monitors.
	mainCtx, mainCancel := signal.NotifyContext(context.Background(), unix.SIGINT, unix.SIGTERM, unix.SIGABRT)
	defer mainCancel()

	beforeCheck := []func() error{
		tracer.ProbeBPFSyscall,
		tracer.ProbeTracepoint,
	}

	for _, check := range beforeCheck {
		if err := check(); err != nil {
			log.Fatal(err)
		}
	}

	presentCores, err := numcpus.GetPresent()
	if err != nil {
		log.Fatalf("Failed to read CPU file: %v", err)
	}

	const (
		monitorInterval       = time.Second * 5
		reporterInterval      = time.Second * 10
		probabilisticInterval = time.Minute
		clockSyncInterval     = time.Minute * 3
		samplesPerSecond      = 19
	)

	intervals := times.New(monitorInterval, reporterInterval, probabilisticInterval)

	// Start periodic synchronization with the realtime clock
	times.StartRealtimeSync(mainCtx, clockSyncInterval)

	log.Tracef("Determining tracers to include")
	includeTracers, _ := tracertypes.Parse("all")

	// Network operations to CA start here
	var (
		rep *reporter.ColaSoft
		cfg = &reporter.ColaSoftConfig{
			Frequency:      samplesPerSecond,
			PresentCores:   presentCores,
			ReportInterval: reporterInterval,
			Intervals:      intervals,
		}
	)
	// Connect to the collection agent
	rep, err = reporter.ColaSoftReporter(mainCtx, cfg)
	if err != nil {
		log.Fatalf("Failed to start reporting: %v", err)
	}

	rep.SetWriter(&Writer{output: "go/profile.json"})
	rep.SetAddr2liner(new(Addr2liners))

	// Now that set the initial host metadata, start a goroutine to keep sending updates regularly.

	// Load the eBPF code and map definitions
	trc, err := tracer.NewTracer(mainCtx, &tracer.Config{
		Reporter:            rep,
		Intervals:           intervals,
		IncludeTracers:      includeTracers,
		FilterErrorFrames:   true,
		SamplesPerSecond:    samplesPerSecond,
		MapScaleFactor:      0,
		KernelVersionCheck:  true,
		BPFVerifierLogLevel: 0,
		BPFVerifierLogSize:  cebpf.DefaultVerifierLogSize,
	})
	if err != nil {
		log.Fatalf("Failed to load eBPF tracer: %v", err)
	}
	log.Printf("eBPF tracer loaded")
	defer trc.Close()

	// Spawn monitors for the various result maps
	traceCh := make(chan *host.Trace)

	chains := []func() error{
		func() error { return trc.StartPIDEventProcessor(mainCtx) },
		trc.AttachTracer,
		trc.EnableProfiling,
		trc.AttachSchedMonitor,
		func() error { return trc.StartMapMonitors(mainCtx, traceCh) },
	}

	for _, call := range chains {
		if err = call(); err != nil {
			log.Fatal(err)
		}
	}

	if _, err = tracehandler.Start(mainCtx, rep, trc.TraceProcessor(), traceCh, intervals, cfg.CacheSize()); err != nil {
		log.Fatalf("Failed to start trace handling: %v", err)
	}

	// Block waiting for a signal to indicate the program should terminate
	<-mainCtx.Done()

	log.Info("Stop processing ...")
	rep.Stop()

	log.Info("Exiting ...")
}
