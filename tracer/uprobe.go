package tracer

import (
	"fmt"
	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"
)

// loadUProbeUnwinders reuses large parts of loadPerfUnwinders. By default all eBPF programs
// are written as perf event eBPF programs. loadUProbeUnwinders dynamically rewrites the
// specification of these programs to kprobe eBPF programs and adjusts tail call maps.
func loadUProbeUnwinders(coll *cebpf.CollectionSpec, ebpfProgs map[string]*cebpf.Program,
	tailcallMap *cebpf.Map, progs []progLoaderHelper,
	bpfVerifierLogLevel uint32, perfTailCallMapFD int) error {
	programOptions := cebpf.ProgramOptions{
		LogLevel: cebpf.LogLevel(bpfVerifierLogLevel),
	}
	for _, unwindProg := range progs {
		if !unwindProg.enable {
			continue
		}

		unwindProgName := unwindProg.name
		if !unwindProg.noTailCallTarget {
			unwindProgName = "kprobe_" + unwindProg.name
		}

		progSpec, ok := coll.Programs[unwindProgName]
		if !ok {
			return fmt.Errorf("program %s does not exist", unwindProgName)
		}

		// Replace the prog array for the tail calls.
		insns := progArrayReferences(perfTailCallMapFD, progSpec.Instructions)
		for _, ins := range insns {
			if err := progSpec.Instructions[ins].AssociateMap(tailcallMap); err != nil {
				return fmt.Errorf("failed to rewrite map ptr: %v", err)
			}
		}

		if err := loadProgram(ebpfProgs, tailcallMap, unwindProg.progID, progSpec,
			programOptions, unwindProg.noTailCallTarget); err != nil {
			return err
		}
	}

	return nil
}

func (t *Tracer) AttachUProbes(execute string, symbol string, canFail bool, needUret bool) {
	prog := symbol + "_enter"
	uProbeProg, ok := t.ebpfProgs[prog]
	var err error
	defer func() {
		if err != nil {
			log.Errorf("failed to attach u-probe program %s: %v", prog, err)
		}
	}()

	if !ok {
		err = fmt.Errorf("prog %s not found", prog)
		return
	}

	exec, err := link.OpenExecutable(execute)
	if err != nil {
		return
	}
	uprobeLink, err := exec.Uprobe(symbol, uProbeProg, nil)
	if err != nil {
		if canFail {
			err = nil
			return
		}
		return
	}
	t.hooks[hookPoint{group: "uprobe", name: execute + ":" + symbol + ":" + prog}] = uprobeLink

	if needUret {
		retProg := symbol + "_exit"
		uRetProbeProg, ok := t.ebpfProgs[retProg]
		if !ok {
			err = fmt.Errorf("prog %s not found", retProg)
		}
		var uRetProbeLink link.Link
		uRetProbeLink, err = exec.Uprobe(symbol, uRetProbeProg, nil)
		if err != nil {
			if canFail {
				err = nil
				return
			}
			return
		}
		t.hooks[hookPoint{group: "uprobe", name: execute + ":" + symbol + ":" + retProg}] = uRetProbeLink
	}
	return
}

// StartCMemProfiling starts off-cpu profiling by attaching the programs to the hooks.
func (t *Tracer) StartCMemProfiling(execute string) error {
	t.AttachUProbes(execute, "malloc", false, true)
	t.AttachUProbes(execute, "calloc", false, true)
	t.AttachUProbes(execute, "realloc", false, true)
	t.AttachUProbes(execute, "mmap", true, true) // failed on jemalloc
	t.AttachUProbes(execute, "posix_memalign", false, true)
	t.AttachUProbes(execute, "valloc", true, true) // failed on Android, is deprecated in libc.so from bionic directory
	t.AttachUProbes(execute, "memalign", false, true)
	t.AttachUProbes(execute, "pvalloc", true, true)       // failed on Android, is deprecated in libc.so from bionic directory
	t.AttachUProbes(execute, "aligned_alloc", true, true) // added in C11
	t.AttachUProbes(execute, "free", false, false)
	t.AttachUProbes(execute, "munmap", true, false) // failed on jemalloc
	return nil
}

// StartCMemProfiling starts off-cpu profiling by attaching the programs to the hooks.
func (t *Tracer) StartPythonMemProfiling(execute string) error {
	// _PyMem_RawCalloc
	//_PyMem_RawMalloc
	//_PyMem_RawRealloc
	//_PyMem_RawFree
	//_PyObject_Malloc
	//_PyObject_Calloc
	//_PyObject_Realloc
	//_PyObject_Free

	t.AttachUProbes(execute, "malloc", false, true)
	t.AttachUProbes(execute, "calloc", false, true)
	t.AttachUProbes(execute, "realloc", false, true)
	t.AttachUProbes(execute, "mmap", true, true) // failed on jemalloc
	t.AttachUProbes(execute, "posix_memalign", false, true)
	t.AttachUProbes(execute, "valloc", true, true) // failed on Android, is deprecated in libc.so from bionic directory
	t.AttachUProbes(execute, "memalign", false, true)
	t.AttachUProbes(execute, "pvalloc", true, true)       // failed on Android, is deprecated in libc.so from bionic directory
	t.AttachUProbes(execute, "aligned_alloc", true, true) // added in C11
	t.AttachUProbes(execute, "free", false, false)
	t.AttachUProbes(execute, "munmap", true, false) // failed on jemalloc
	return nil
}
