package tracer

import (
	"fmt"
	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"
	"github.com/toliu/opentelemetry-ebpf-profiler/process"
	"runtime"
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

func (t *Tracer) AttachUProbesWithProgPrefix(execute string, symbol string, progPrefix string, canFail bool, needUret bool, pid int) {
	prog := symbol + "_enter"
	if progPrefix != "" {
		prog = progPrefix + "_enter"
	}
	var opts *link.UprobeOptions
	if pid > 0 {
		opts = &link.UprobeOptions{PID: pid}
	}
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
	uprobeLink, err := exec.Uprobe(symbol, uProbeProg, opts)
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
		if progPrefix != "" {
			retProg = progPrefix + "_exit"
		}
		uRetProbeProg, ok := t.ebpfProgs[retProg]
		if !ok {
			err = fmt.Errorf("prog %s not found", retProg)
		}
		var uRetProbeLink link.Link
		uRetProbeLink, err = exec.Uretprobe(symbol, uRetProbeProg, opts)
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

// StartCLikeMemProfiling starts off-cpu profiling for c/c++/rust by attaching the programs to the hooks.
func (t *Tracer) StartCLikeMemProfiling(execute string, pid int) bool {
	if execute == "" {
		return false
	}
	t.AttachUProbesWithProgPrefix(execute, "malloc", "", false, true, pid)
	t.AttachUProbesWithProgPrefix(execute, "calloc", "", false, true, pid)
	t.AttachUProbesWithProgPrefix(execute, "realloc", "", false, true, pid)
	t.AttachUProbesWithProgPrefix(execute, "mmap", "", true, true, pid) // failed on jemalloc
	t.AttachUProbesWithProgPrefix(execute, "posix_memalign", "", false, true, pid)
	t.AttachUProbesWithProgPrefix(execute, "valloc", "", true, true, pid) // failed on Android, is deprecated in libc.so from bionic directory
	t.AttachUProbesWithProgPrefix(execute, "memalign", "", false, true, pid)
	t.AttachUProbesWithProgPrefix(execute, "pvalloc", "", true, true, pid)       // failed on Android, is deprecated in libc.so from bionic directory
	t.AttachUProbesWithProgPrefix(execute, "aligned_alloc", "", true, true, pid) // added in C11
	t.AttachUProbesWithProgPrefix(execute, "free", "", false, false, pid)
	t.AttachUProbesWithProgPrefix(execute, "munmap", "", true, false, pid) // failed on jemalloc
	return true
}

// StartPythonMemProfiling StartCMemProfiling starts off-cpu profiling by attaching the programs to the hooks.
func (t *Tracer) StartPythonMemProfiling(execute string, libc string, pid int) bool {
	if execute == "" || libc == "" {
		return false
	}
	t.AttachUProbesWithProgPrefix(execute, "PyObject_Malloc", "", false, true, pid)
	t.AttachUProbesWithProgPrefix(execute, "PyObject_Calloc", "", false, true, pid)
	t.AttachUProbesWithProgPrefix(execute, "PyObject_Realloc", "", false, true, pid)
	t.AttachUProbesWithProgPrefix(execute, "PyObject_Free", "", false, false, pid)

	t.AttachUProbesWithProgPrefix(execute, "PyMem_Malloc", "", false, true, pid)
	t.AttachUProbesWithProgPrefix(execute, "PyMem_Calloc", "", false, true, pid)
	t.AttachUProbesWithProgPrefix(execute, "PyMem_Realloc", "", false, true, pid)
	t.AttachUProbesWithProgPrefix(execute, "PyMem_Free", "", false, false, pid)

	//t.AttachUProbes(execute, "PyMem_RawMalloc", false, true)
	//t.AttachUProbes(execute, "PyMem_RawCalloc", false, true)
	//t.AttachUProbes(execute, "PyMem_RawRealloc", false, true)
	//t.AttachUProbes(execute, "PyMem_RawFree", false, false)
	t.AttachUProbesWithProgPrefix(libc, "malloc", "Py_Malloc", false, true, pid)
	t.AttachUProbesWithProgPrefix(libc, "calloc", "Py_Calloc", false, true, pid)
	t.AttachUProbesWithProgPrefix(libc, "realloc", "Py_Realloc", false, true, pid)
	t.AttachUProbesWithProgPrefix(libc, "free", "Py_Free", false, false, pid)
	return true
}

func (t *Tracer) StartGoMemProfiling(execute string, pid int, isRegister bool) bool {
	if execute == "" {
		return false
	}
	progPrefix := "mallocgc_register"
	if !isRegister {
		progPrefix = "mallocgc_stack"
	}
	t.AttachUProbesWithProgPrefix(execute, "runtime.mallocgc", progPrefix, false, false, pid)
	return true
}

func (t *Tracer) TriggerMemProfile(p process.Process) bool {
	if memProfileInfo := t.processManager.GetMemProfileInfo(p.PID()); memProfileInfo != nil {
		switch memProfileInfo.Lang {
		case "Python":
			if memProfileInfo.MajorVersion >= 3 && memProfileInfo.MinorVersion >= 10 { // after 3.10
				return t.StartPythonMemProfiling(memProfileInfo.ExecAbsPath, memProfileInfo.LibcPath, int(p.PID()))
			}
		case "Java":
			if memProfileInfo.MajorVersion >= 11 && memProfileInfo.MinorVersion >= 0 { // after java 11
				return true
			}
		case "go":
			isRegister := true
			switch runtime.GOARCH {
			case "amd64":
				if memProfileInfo.MinorVersion < 17 {
					isRegister = false
				}
			case "arm64":
				if memProfileInfo.MinorVersion < 18 {
					isRegister = false
				}
			}
			t.StartGoMemProfiling(memProfileInfo.ExecAbsPath, int(p.PID()), isRegister) // todo
		case "": // rust c c++
			t.StartCLikeMemProfiling(memProfileInfo.LibcPath, int(p.PID())) // todo
		default:
			return true
		}
		return true
	}
	return false
}

func (t *Tracer) SyncMemProfile(pids []process.Process) {
	for _, p := range pids {
		t.processManager.SynchronizeProcess(p)
		t.TriggerMemProfile(p)
	}
}
