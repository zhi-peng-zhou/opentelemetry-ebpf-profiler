package main

import "C"
import (
	"bufio"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	jsoniter "github.com/json-iterator/go"
	"github.com/toliu/opentelemetry-ebpf-profiler/support"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

type SymbolResolver struct {
	pid      int
	maps     []MemoryMapping
	symCache map[string]*elf.File
}

type MemoryMapping struct {
	Start    uint64
	End      uint64
	Perms    string
	Offset   uint64
	Dev      string
	Inode    uint64
	Pathname string
}

func NewSymbolResolver(pid int) (*SymbolResolver, error) {
	resolver := &SymbolResolver{
		pid:      pid,
		symCache: make(map[string]*elf.File),
	}

	err := resolver.loadMemoryMaps()
	if err != nil {
		return nil, err
	}

	return resolver, nil
}

func (r *SymbolResolver) loadMemoryMaps() error {
	file, err := os.Open(fmt.Sprintf("/proc/%d/maps", r.pid))
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}

		// 解析地址范围
		addrs := strings.Split(parts[0], "-")
		if len(addrs) != 2 {
			continue
		}

		start, _ := strconv.ParseUint(addrs[0], 16, 64)
		end, _ := strconv.ParseUint(addrs[1], 16, 64)
		offset, _ := strconv.ParseUint(parts[2], 16, 64)
		inode, _ := strconv.ParseUint(parts[4], 16, 64)

		mapping := MemoryMapping{
			Start:    start,
			End:      end,
			Perms:    parts[1],
			Offset:   offset,
			Dev:      parts[3],
			Inode:    inode,
			Pathname: parts[len(parts)-1],
		}

		r.maps = append(r.maps, mapping)
	}

	return scanner.Err()
}

func (r *SymbolResolver) Resolve(addr uint64, showModule, showOffset bool) (string, error) {
	// 查找地址所属的映射
	var mapping *MemoryMapping
	for _, m := range r.maps {
		if addr >= m.Start && addr < m.End {
			mapping = &m
			break
		}
	}

	if mapping == nil {
		return fmt.Sprintf("0x%x", addr), nil
	}

	// 计算相对偏移
	offset := addr - mapping.Start + mapping.Offset

	if mapping.Pathname == "" || strings.HasPrefix(mapping.Pathname, "[") {
		// 匿名映射
		return fmt.Sprintf("[anonymous+0x%x]", offset), nil
	}

	// 解析符号
	symName, symOffset, err := r.resolveSymbolInFile(mapping.Pathname, offset)
	if err != nil {
		return fmt.Sprintf("%s[0x%x]", mapping.Pathname, offset), nil
	}

	var result string
	if showModule {
		result = mapping.Pathname + "["
	}

	result += symName

	if showOffset && symOffset > 0 {
		result += fmt.Sprintf("+%d", symOffset)
	}

	if showModule {
		result += "]"
	}

	return result, nil
}

func (r *SymbolResolver) resolveSymbolInFile(filepath string, offset uint64) (string, uint64, error) {
	// 缓存 ELF 文件
	elfFile, ok := r.symCache[filepath]
	if !ok {
		var err error
		elfFile, err = elf.Open(filepath)
		if err != nil {
			return "", offset, err
		}
		r.symCache[filepath] = elfFile
	}

	// 查找符号
	symbols, err := elfFile.Symbols()
	if err != nil {
		return "", offset, err
	}

	var closestSym *elf.Symbol
	var closestOffset uint64

	for _, sym := range symbols {
		if sym.Value <= offset {
			if closestSym == nil || sym.Value > closestSym.Value {
				closestSym = &sym
				closestOffset = offset - sym.Value
			}
		}
	}

	if closestSym != nil {
		return closestSym.Name, closestOffset, nil
	}

	return "", offset, fmt.Errorf("symbol not found")
}

type event struct {
	Size         uint64
	Timestamp_ns uint64
	Pid          uint64
	Stack_id     uint32
	Type_t       uint32
}

// FindProcessByPID 根据PID查找进程信息
func FindProcessByPID(pid uint64) (*ProcessInfo, error) {
	info := &ProcessInfo{PID: pid}

	// 检查进程是否存在
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(err) {
		return nil, fmt.Errorf("进程不存在: %d", pid)
	}

	// 获取命令行
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	cmdlineData, err := os.ReadFile(cmdlinePath)
	if err == nil {
		cmdline := string(cmdlineData)
		info.Command = strings.ReplaceAll(cmdline, "\x00", " ")
		info.Args = strings.Split(strings.Trim(cmdline, "\x00"), "\x00")
	}

	// 获取可执行文件路径
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	if realPath, err := os.Readlink(exePath); err == nil {
		info.ExePath = realPath
	}

	return info, nil
}

func linkUprobePid(pid int, symble string, p, retp *cebpf.Program, needRet bool) ([]link.Link, error) {
	//option := &link.UprobeOptions{PID: pid}

	//procPath := fmt.Sprintf("/proc/%d/exe", pid)
	filePath := "/usr/lib/x86_64-linux-gnu/libc.so.6"

	// 读取符号链接的目标路径
	//filePath, err := os.Readlink(procPath)
	//if err != nil {
	//	fmt.Println("filePath: error", err.Error())
	//	return nil, err
	//}

	var uLink, rLink link.Link

	file, err := link.OpenExecutable(filePath)
	if err != nil {
		fmt.Println("OpenExecutable error:", err)
		return nil, err
	}

	if uLink, err = file.Uprobe(symble, p, nil); err != nil {
		fmt.Println("Uprobe error:", err)
		return nil, err
	}

	if needRet {
		if rLink, err = file.Uretprobe(symble, retp, nil); err != nil {
			fmt.Println("Uretprobe error:", err)
			return nil, err
		}
	}

	return []link.Link{uLink, rLink}, nil
}

type ProcessInfo struct {
	PID     uint64
	Command string
	ExePath string
	Args    []string
	mem     int64
	stack   []string
}
type memInfo struct {
	PID   uint64
	Mem   uint64
	Stack []string
}

func main() {
	args := os.Args[1:]
	var pid int
	var err error
	if len(args) > 0 {
		pid, err = strconv.Atoi(args[0])
		fmt.Println("pid:", pid)
		if err != nil {
			fmt.Println(err)
		}
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Println("failed to remove mem lock: %v", err)
		return
	}

	memAllocMap := make(map[uint32]memInfo)
	coll, err := support.LoadCollectionSpec(false)
	if err != nil {
		fmt.Println("Error loading collection spec:", err)
		return
	}
	ebpfMaps := make(map[string]*cebpf.Map)
	ebpfProgs := make(map[string]*cebpf.Program)

	maps := []string{"stack_traces", "size_record", "comvined_alloc_infos", "alloc_infos", "events", "memptrs"}
	for mapName, mapSpec := range coll.Maps {
		if slices.Contains(maps, mapName) {
			ebpfMap, err := cebpf.NewMap(mapSpec)
			if err != nil {
				fmt.Printf("failed to load %s: %v \n", mapName, err)
			}
			ebpfMaps[mapName] = ebpfMap
		}
	}
	//fmt.Printf("Loaded %v maps\n", ebpfMaps)
	err = coll.RewriteMaps(ebpfMaps)
	if err != nil {
		fmt.Printf("failed to rewrite maps: %v", err)
		return
	}

	if err != nil {
		fmt.Println("Error loading collection spec:", err)
		return
	}

	progs := []string{"kmalloc", "kfree", "malloc_enter", "malloc_exit", "ufree_enter",
		"calloc_enter", "calloc_exit", "realloc_enter", "realloc_exit", "mmap_enter", "mmap_exit", "munmap_enter",
		"posix_memalign_enter", "posix_memalign_exit", "aligned_alloc_enter", "aligned_alloc_exit", "valloc_enter", "valloc_exit",
		"memalign_enter", "memalign_exit", "pvalloc_enter", "pvalloc_exit"}
	for pName, p := range coll.Programs {
		if slices.Contains(progs, pName) {
			ebpfProgs[pName], err = cebpf.NewProgram(p)
			if err != nil {
				fmt.Printf("failed to load %s: %v \n", pName, err)
				return
			}
		}

	}

	//
	//km, e1 := link.Tracepoint("kmem", "kmalloc", ebpfProgs["kmalloc"], nil)
	//kf, e2 := link.Tracepoint("kmem", "kfree", ebpfProgs["kfree"], nil)
	//if e1 != nil || e2 != nil {
	//	fmt.Println("failed to link kmalloc: %v", errors.Join(e1, e2))
	//	return
	//}
	//defer func() {
	//	km.Close()
	//	kf.Close()
	//}()
	var sr *SymbolResolver
	if pid > 0 {
		sr, err = NewSymbolResolver(int(pid))
		if err != nil {
			fmt.Println("NewSymbolResolver error:", err)
			return
		}
	}

	links, err := linkUprobePid((pid), "malloc", ebpfProgs["malloc_enter"], ebpfProgs["malloc_exit"], true)

	if err != nil {
		fmt.Println("Uprobe error:", err)
		return
	}
	fmt.Println("Uprobe success")
	for _, link := range links {
		defer link.Close()
	}

	freeLinks, freeErr := linkUprobePid(int(pid), "free", ebpfProgs["ufree_enter"], nil, false)
	if freeErr != nil {
		fmt.Println("Uprobe error:", freeErr)
		return
	}
	fmt.Println("Uprobe success")
	for _, link := range freeLinks {
		if link != nil {
			defer link.Close()
		}
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	rd, err := perf.NewReader(ebpfMaps["events"], os.Getpagesize())
	if err != nil {
		fmt.Println("failed to new reader: %v", err)
		return
	}
	defer rd.Close()

	procInfos := make(map[uint64]*ProcessInfo, 0)

	for {
		for {
			select {
			case <-ticker.C:
				//fmt.Println("=====================================")
				//for pid, p := range procInfos {
				//	fmt.Printf("pid: %d(%s) mem %d \n", pid, p.Command, p.mem)
				//}
				//fmt.Println("-------------------------------------")
			default:
				// Continue execution below.
				record, err := rd.Read()
				if err != nil {
					fmt.Printf("failed to read record: %v \n", err)
					break
				}
				var e event
				err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e)
				if err != nil {
					fmt.Printf("failed to read event: %v\n", err)
					break
				}
				i, ok := procInfos[e.Pid]
				if !ok {
					if info, err := FindProcessByPID(e.Pid); err != nil {
						continue
					} else {
						procInfos[e.Pid] = info
					}
				}
				i, _ = procInfos[e.Pid]
				stackMap := ebpfMaps["stack_traces"]
				key := e.Stack_id
				kstackVal := make([]uint64, 16)
				if stackMap.Lookup(&key, &kstackVal) != nil {
					fmt.Printf("failed to find kstack val for pid: %d\n", e.Pid)
					continue
				}
				if sr != nil && !ok {
					for _, k := range kstackVal {
						if k == 0 {
							break
						}
						sy, err := sr.Resolve(k, true, true)
						if err != nil {
							fmt.Printf("failed to resolve kstack val for pid: %d\n", e.Pid)
							continue
						}
						i.stack = append(i.stack, sy)
					}
				}

				fmt.Printf("mem alloc for pid: %d, stack: %v, size: %d, , type: %d\n", e.Pid, i.stack, e.Size, e.Type_t)
				size := e.Size
				if e.Type_t == 0 {
					size = 0 - size
				}
				if cache, ok := memAllocMap[e.Stack_id]; ok {
					cache.Mem = cache.Mem + size
					memAllocMap[e.Stack_id] = cache
				} else {
					c := &memInfo{PID: e.Pid, Mem: size, Stack: i.stack}
					memAllocMap[e.Stack_id] = *c
				}
				js, _ := jsoniter.MarshalIndent(memAllocMap, "", " ")
				fmt.Printf("memallocInfo : %s \n", js)
				//fmt.Println("kstack val:", i.stack)
				if e.Type_t == 1 {
					i.mem = int64(e.Size) + i.mem
				} else {
					i.mem -= i.mem - int64(e.Size)
				}
			}
		}
	}

}
