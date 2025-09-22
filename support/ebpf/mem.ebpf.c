#include "bpfdefs.h"
#include "frametypes.h"
#include "stackdeltatypes.h"
#include "tracemgmt.h"
#include "types.h"
#include "tsd.h"

// c: 1000-0000-0000-0000       0000-0000-0000-0000
#define KERNEL 0
#define MALLOC 1
#define CALLOC 2
#define REALLOC 3
#define MMAP 4
#define POSIX_MEMALIGN 5
#define VALLOC 6
#define MEMALIGN 7
#define PVALLOC 8
#define ALIGNED_ALLOC 9
#define FREE 10
#define MUNMAP 11

// py-raw 0100-0000-0000-0000       0000-0000-0000-0000
#define PYRAWMALLOC 12
#define PYRAWCALLOC 13
#define PYRAWREALLOC 14

// py-alloc 0010-0000-0000-0000       0000-0000-0000-0000
#define PYMALLOC 16
#define PYCALLOC 17
#define PYREALLOC 18

//#define PYMEMMALLOC 20
//#define PYMEMCALLOC 21
//#define PYMEMREALLOC 22


//#define deDEBUG_FLAGS 1

#define printt(fmt, ...)                                                                         \
({                                                                                             \
  const char ____fmt[] = fmt "\n";                                                             \
  bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                                   \
})



struct kmalloc_event {
    unsigned long pad;

    unsigned long call_site;
    const void *ptr;
    unsigned long bytes_req;
    unsigned long bytes_alloc;
    unsigned int gfp_flags;   // 分配标志
};

struct kfree_event {
    unsigned long pad;
    unsigned long call_site;
    const void *ptr;        // kfree 释放的地址
};

// 对应 kmem_cache_alloc tracepoint 的事件结构体
struct kmem_cache_alloc_event {
    unsigned long pad;

    // kmem_cache_alloc 特有的字段
    unsigned long call_site;           // 分配调用站点（offset 8, size 8）
    const void *ptr;                   // 分配的内存指针（offset 16, size 8）
    size_t bytes_req;                  // 请求分配的字节数（offset 24, size 8）
    size_t bytes_alloc;                // 实际分配的字节数（offset 32, size 8）
    u32 gfp_flags;                   // 内存分配标志（offset 40, size 4）
};

struct kmem_cache_free_event {
    // 通用事件头（所有 tracepoint 共有的字段）
    unsigned long pad;

    // kmem_cache_free 特有的字段
    unsigned long call_site;           // 释放调用站点（offset 8, size 8）
    const void *ptr;                   // 待释放的内存指针（offset 16, size 8）
    char name[4];           // 内存缓存名称的偏移量（offset 24, size 4）
};

// 对应 mm_page_alloc tracepoint 的事件结构体
struct mm_page_alloc_event {
    // 通用事件头（所有 tracepoint 共有的字段）
    unsigned long pad;

    // mm_page_alloc 特有的字段
    unsigned long pfn;                 // 页帧号（offset 8, size 8）
    unsigned int order;                // 分配阶数（offset 16, size 4）
    u32 gfp_flags;                   // 内存分配标志（offset 20, size 4）
    int migratetype;                   // 迁移类型（offset 24, size 4）
};

// 对应 mm_page_free tracepoint 的事件结构体
struct mm_page_free_event {
    // 通用事件头（所有 tracepoint 共有的字段）
   unsigned long pad;

    // mm_page_free 特有的字段
    unsigned long pfn;                 // 页帧号（offset 8, size 8）
    unsigned int order;                // 释放阶数（offset 16, size 4）
};


typedef struct {
    u64 size;
    u64 timestamp_ns;
    u64 pid;
    u32 stack_id;
    u32 type_t;
} event;

typedef struct {
    u64 total_size;
    u64 mem_allocs;
} combined_alloc_info_t;


bpf_map_def SEC("maps") size_record = {
  .type        = BPF_MAP_TYPE_HASH,
  .key_size    = sizeof(u64),
  .value_size  = sizeof(u64),
  .max_entries = 1000000,
};

bpf_map_def SEC("maps") alloc_infos = {
  .type        = BPF_MAP_TYPE_HASH,
  .key_size    = sizeof(u64),
  .value_size  = sizeof(size_t),
  .max_entries = 1000000,
};

bpf_map_def SEC("maps") memptrs = {
  .type        = BPF_MAP_TYPE_HASH,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(u64),
  .max_entries = 1000000,
};

static inline __attribute__((__always_inline__)) int alloc_enter(struct pt_regs *ctx, size_t size, u32 type_index) {
//    if (type_index == PYMALLOC || type_index == PYCALLOC || type_index == PYREALLOC) {
//        u32 tid = bpf_get_current_pid_tgid();
//        u64 key_py_malloc = (u64)PYMALLOC << 32 | tid;
//        u64* size64 = bpf_map_lookup_elem(&size_record, &key_py_malloc);
//        if (size64)
//            return 0;
//        u64 key_py_calloc = (u64)PYCALLOC << 32 | tid;
//        size64 = bpf_map_lookup_elem(&size_record, &key_py_calloc);
//        if (size64)
//            return 0;
//        u64 key_py_realloc = (u64)PYREALLOC << 32 | tid;
//        size64 = bpf_map_lookup_elem(&size_record, &key_py_realloc);
//        if (size64)
//            return 0;
//    }
    u32 tid = bpf_get_current_pid_tgid();
    u64 s = size;
    u64 key = (u64)type_index << 32 | tid;
    bpf_map_update_elem(&size_record, &key, &s, BPF_ANY);
    printt("alloc_enter size: %lu, type: %d",size, type_index);
    return 0;
}

static inline __attribute__((__always_inline__)) u64 alloc_exit2(struct pt_regs *ctx, u64 address, u32 type_index) {
    u64 id  = bpf_get_current_pid_tgid();
    u32 tid = id & 0xFFFFFFFF;
    u64 key = (u64)type_index << 32 | tid;
    u64* size64 = bpf_map_lookup_elem(&size_record, &key);
    if (!size64)
        return 0;
    bpf_map_delete_elem(&size_record, &key);
    if (address == 0)
        return 0;
    u32 pid = id >> 32;
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&alloc_infos, &address, size64, BPF_ANY);
    printt("alloc_exit2 address: %llu, type: %u",address, type_index);
    return collect_trace(ctx, TRACE_HEAP_ALLOC, pid, tid, ts, 1, *size64);
}

static inline __attribute__((__always_inline__)) int alloc_exit(struct pt_regs *ctx, u32 type_index) {
        return alloc_exit2(ctx, PT_REGS_RC(ctx), type_index);
}

static inline __attribute__((__always_inline__)) u64 free_entry(struct pt_regs *ctx, void *address) {
    u64 addr = (u64)address;
    size_t* s = bpf_map_lookup_elem(&alloc_infos, &addr);
    if (!s)
        return 0;
    u64 id  = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id & 0xFFFFFFFF;
    bpf_map_delete_elem(&alloc_infos, &addr);
    u64 ts = bpf_ktime_get_ns();
    printt("free_entry address: %llu, size: %lu",addr, *s);
    return collect_trace(ctx, TRACE_HEAP_ALLOC, pid, tid, ts, 0, *s);
}


SEC("uprobe/malloc")
int malloc_enter(struct pt_regs *ctx) {
    size_t actual_size = (size_t)PT_REGS_PARM1(ctx);
    return alloc_enter(ctx, actual_size, MALLOC);
}

SEC("uretprobe/malloc")
int malloc_exit(struct pt_regs *ctx) {
    return alloc_exit2(ctx, PT_REGS_RC(ctx), MALLOC);

}

SEC("uprobe/free")
int free_enter(struct pt_regs *ctx) {
    void *address = (void *)PT_REGS_PARM1(ctx);
    return free_entry(ctx, address);
}

SEC("uprobe/calloc")
int calloc_enter(struct pt_regs *ctx) {
    size_t nmemb = (size_t)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM2(ctx);
    return alloc_enter(ctx, nmemb * size, CALLOC);
}
SEC("uretprobe/calloc")
int calloc_exit(struct pt_regs *ctx) {
    return alloc_exit(ctx, CALLOC);
}
SEC("uprobe/realloc")
int realloc_enter(struct pt_regs *ctx) {
    void *ptr = (void *)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM2(ctx);
    alloc_enter(ctx, size, REALLOC);
    return free_entry(ctx, ptr);
}

SEC("uretprobe/realloc")
int realloc_exit(struct pt_regs *ctx) {
    return alloc_exit(ctx, REALLOC);
}

SEC("uprobe/mmap")
int mmap_enter(struct pt_regs *ctx) {
    size_t size = (size_t)PT_REGS_PARM2(ctx);
    return alloc_enter(ctx, size, MMAP);
}
SEC("uretprobe/mmap")
int mmap_exit(struct pt_regs *ctx) {
    return alloc_exit(ctx, MMAP);
}
SEC("uprobe/munmap")
int munmap_enter(struct pt_regs *ctx) {
    void *address = (void *)PT_REGS_PARM2(ctx);
    return free_entry(ctx, address);
}

SEC("uprobe/posix_memalign")
int posix_memalign_enter(struct pt_regs *ctx) {
    void ** memptr = (void **)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM3(ctx);

    u64 memptr64 = (u64)(size_t)memptr;
    u32 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&memptrs, &tid, &memptr64,BPF_ANY);
    return alloc_enter(ctx, size, POSIX_MEMALIGN);
}

SEC("uretprobe/posix_memalign")
int posix_memalign_exit(struct pt_regs *ctx) {
    u64 id  = bpf_get_current_pid_tgid();
    u32 tid = id & 0xFFFFFFFF;
    u64 *memptr64 = bpf_map_lookup_elem(&memptrs, &tid);
    void *addr;
    if (memptr64 == 0)
            return 0;
    bpf_map_delete_elem(&memptrs, &tid);
    if (bpf_probe_read_user(&addr, sizeof(void*), (void*)(size_t)*memptr64))
            return 0;
    u64 addr64 = (u64)(size_t)addr;
    return alloc_exit2(ctx, addr64, POSIX_MEMALIGN);
}

SEC("uprobe/aligned_alloc")
int aligned_alloc_enter(struct pt_regs *ctx) {
    size_t size = (size_t)PT_REGS_PARM2(ctx);
    return alloc_enter(ctx, size, ALIGNED_ALLOC);
}

SEC("uretprobe/aligned_alloc")
int aligned_alloc_exit(struct pt_regs *ctx) {
    return alloc_exit(ctx, ALIGNED_ALLOC);
}

SEC("uprobe/valloc")
int valloc_enter(struct pt_regs *ctx) {
    size_t size = (size_t)PT_REGS_PARM1(ctx);
    return alloc_enter(ctx, size, VALLOC);
}

SEC("uretprobe/valloc")
int valloc_exit(struct pt_regs *ctx) {
    return alloc_exit(ctx, VALLOC);
}

SEC("uprobe/memalign")
int memalign_enter(struct pt_regs *ctx) {
    size_t size = (size_t)PT_REGS_PARM2(ctx);
    return alloc_enter(ctx, size, MEMALIGN);
}

SEC("uretprobe/memalign")
int memalign_exit(struct pt_regs *ctx) {
    return alloc_exit(ctx, MEMALIGN);
}

SEC("uprobe/pvalloc")
int pvalloc_enter(struct pt_regs *ctx) {
    size_t size = (size_t)PT_REGS_PARM1(ctx);
    return alloc_enter(ctx, size, PVALLOC);
}

SEC("uretprobe/pvalloc")
int pvalloc_exit(struct pt_regs *ctx) {
    return alloc_exit(ctx, PVALLOC);
}


//SEC("tracepoint/kmem/kfree")
//int kfree(struct kfree_event *info)
//{
//    int s = free_enter((struct pt_regs *)info, (void *)info->ptr);
//    u64 ts = bpf_ktime_get_ns();
//    u64 id  = bpf_get_current_pid_tgid();
//    u32 pid = id >> 32;
//    u32 tid = id & 0xFFFFFFFF;
//    return collect_trace(info, TRACE_HEAP_ALLOC, pid, tid, ts, 0, s);
//}
//
//SEC("tracepoint/kmem/kmalloc")
//int kmalloc(struct kmalloc_event *info)
//{
//    alloc_enter((struct pt_regs *)info, info-> bytes_alloc, MALLOC);
//    int s = alloc_exit2((struct pt_regs *)info, (u64)info->ptr, MALLOC);
//    u64 ts = bpf_ktime_get_ns();
//    u64 id  = bpf_get_current_pid_tgid();
//    u32 pid = id >> 32;
//    u32 tid = id & 0xFFFFFFFF;
//    return collect_trace(info, TRACE_HEAP_ALLOC, pid, tid, ts, 0, s);
//}

//
//SEC("tracepoint/kmem/kmem_cache_alloc")
//int kmem_cache_alloc(struct kmem_cache_alloc_event *info)
//{
//    if (WORKAROUND_MISSING_FREE)
//        free_enter((struct pt_regs *)info, (void *)info->ptr);
//    alloc_enter((struct pt_regs *)info, info->bytes_alloc, KERNEL);
//    return alloc_exit2((struct pt_regs *)info, (size_t)info->ptr, KERNEL);
//}
//
//
//SEC("tracepoint/kmem/kmem_cache_free")
//int kmem_cache_free(struct kmem_cache_free_event *info)
//{
//    return free_enter((struct pt_regs *)info, (void *)info->ptr);
//}
//
//
//SEC("tracepoint/kmem/mm_page_alloc")
//int mm_page_alloc(struct mm_page_alloc_event *info)
//{
//        alloc_enter((struct pt_regs *)info, PAGE_SIZE << info->order, KERNEL);
//        return alloc_exit2((struct pt_regs *)info, info->pfn, KERNEL);
//}
//
//SEC("tracepoint/kmem/mm_page_free")
//int mm_page_free(struct mm_page_free_event *info)
//{
//    return free_enter((struct pt_regs *)info, (void *)info->pfn);
//}


// uprobe__generic serves as entry point for uprobe based profiling.
//SEC("uprobe/generic")
//int uprobe__generic(void *ctx)
//{
//  u64 pid_tgid = bpf_get_current_pid_tgid();
//  u32 pid      = pid_tgid >> 32;
//  u32 tid      = pid_tgid & 0xFFFFFFFF;
//
//  if (pid == 0 || tid == 0) {
//    return 0;
//  }
//
//  u64 ts = bpf_ktime_get_ns();
//
//  return collect_trace(ctx, TRACE_UPROBE, pid, tid, ts, 0);
//}

//
///** pymem_raw **/
//// void * PyMem_RawMalloc(size_t size)
//SEC("uprobe/pymem_rawmalloc")
//int PyMem_RawMalloc_enter(struct pt_regs *ctx)
//{
//    size_t nbytes = PT_REGS_PARM1(ctx);
//    return alloc_enter(ctx, nbytes, PYRAWMALLOC);
//}
//
//// // void * PyMem_RawMalloc(size_t size)
//SEC("uretprobe/pymem_rawmalloc")
//int PyMem_RawMalloc_exit(struct pt_regs *ctx)
//{
//    return alloc_exit2(ctx, PT_REGS_RC(ctx), PYRAWMALLOC);
//}
//
//// void * PyMem_RawCalloc(size_t nelem, size_t elsize)
//SEC("uprobe/pymem_rawcalloc")
//int PyMem_RawCalloc_enter(struct pt_regs *ctx)
//{
//    size_t nelem = (size_t)PT_REGS_PARM1(ctx);
//    size_t elsize = (size_t)PT_REGS_PARM2(ctx);
//    return alloc_enter(ctx, nelem * elsize, PYRAWCALLOC);
//}
//
//// void * PyMem_RawCalloc(size_t nelem, size_t elsize)
//SEC("uretprobe/pymem_rawcalloc")
//int PyMem_RawCalloc_exit(struct pt_regs *ctx)
//{
//    return alloc_exit2(ctx, PT_REGS_RC(ctx), PYRAWCALLOC);
//}
//
//// void* PyMem_RawRealloc(void *ptr, size_t new_size)
//SEC("uprobe/pymem_rawrealloc")
//int PyMem_RawRealloc_enter(struct pt_regs *ctx) {
//    void *ptr = (void *)PT_REGS_PARM1(ctx);
//    size_t size = (size_t)PT_REGS_PARM2(ctx);
//    alloc_enter(ctx, size, PYRAWREALLOC);
//    return free_entry(ctx, ptr);
//}
//
//// void* PyMem_RawRealloc(void *ptr, size_t new_size)
//SEC("uretprobe/pymem_rawrealloc")
//int PyMem_RawRealloc_exit(struct pt_regs *ctx) {
//    return alloc_exit(ctx, PYRAWREALLOC);
//}
//
//// void PyMem_RawFree(void *ptr)
//SEC("uprobe/pymem_rawfree")
//int PyMem_RawFree_enter(struct pt_regs *ctx) {
//    void *address = (void *)PT_REGS_PARM1(ctx);
//    return free_entry(ctx, address);
//}

/** pyobj **/
// void * PyObject_Malloc(size_t size)
SEC("uprobe/pyobj_malloc")
int PyObject_Malloc_enter(struct pt_regs *ctx)
{
    size_t nbytes = PT_REGS_PARM1(ctx);
    printt("pyobj_malloc nbytes: %lu", nbytes);
    return alloc_enter(ctx, nbytes, PYMALLOC);
}

// void * PyObject_Malloc(size_t size)
SEC("uretprobe/pyobj_malloc")
int PyObject_Malloc_exit(struct pt_regs *ctx)
{
    printt("pyobj_malloc exit: %d", 1);
    return alloc_exit2(ctx, PT_REGS_RC(ctx), PYMALLOC);
}

// void * PyObject_Calloc(size_t nelem, size_t elsize)
SEC("uprobe/pyobj_calloc")
int PyObject_Calloc_enter(struct pt_regs *ctx)
{
    size_t nelem = (size_t)PT_REGS_PARM1(ctx);
    size_t elsize = (size_t)PT_REGS_PARM2(ctx);
    printt("pyobj_calloc elsize： %lu, nelem: %lu", elsize, nelem);
    return alloc_enter(ctx, nelem * elsize, PYCALLOC);
}

// void * PyObject_Calloc(size_t nelem, size_t elsize)
SEC("uretprobe/pyobj_calloc")
int PyObject_Calloc_exit(struct pt_regs *ctx)
{
    printt("pyobj_calloc exit %d", 1);
    return alloc_exit2(ctx, PT_REGS_RC(ctx), PYCALLOC);
}

// void * PyObject_Realloc(void *ptr, size_t new_size)
// ptr here maybe 0, then cpython will use _PyObject_Malloc
SEC("uprobe/pyobj_realloc")
int PyObject_Realloc_enter(struct pt_regs *ctx) {
    size_t size = (size_t)PT_REGS_PARM2(ctx);
    printt("pyobj_realloc size： %lu", size);
    alloc_enter(ctx, size, PYREALLOC);
    void *ptr = (void *)PT_REGS_PARM1(ctx);
    return free_entry(ctx, ptr);
//    if (!ptr)
//        return 0;
}

// void * PyObject_Realloc(void *ptr, size_t new_size)
SEC("uretprobe/pyobj_realloc")
int PyObject_Realloc_exit(struct pt_regs *ctx) {
    printt("pyobj_realloc exit： %d", 1);
    return alloc_exit(ctx, PYREALLOC);
}

// void PyObject_Free(void *ptr)
SEC("uprobe/pyobj_free")
int PyObject_Free_enter(struct pt_regs *ctx) {
    printt("pyobj_free ： %d",1);
    void *address = (void *)PT_REGS_PARM1(ctx);
    return free_entry(ctx, address);
}


/** PyMem **/
// void * PyMem_Malloc(size_t size)
SEC("uprobe/pymem_malloc")
int PyMem_Malloc_enter(struct pt_regs *ctx)
{
    size_t nbytes = PT_REGS_PARM1(ctx);
    printt("pymem_malloc size： %lu", nbytes);
    return alloc_enter(ctx, nbytes, PYMALLOC);
}

// void * PyMem_Malloc(size_t size)
SEC("uretprobe/pymem_malloc")
int PyMem_Malloc_exit(struct pt_regs *ctx)
{
    printt("pymem_malloc exit： %d", 1);
    return alloc_exit2(ctx, PT_REGS_RC(ctx), PYMALLOC);
}

// void * PyMem_Calloc(size_t nelem, size_t elsize)
SEC("uprobe/pymem_calloc")
int PyMem_Calloc_enter(struct pt_regs *ctx)
{
    size_t nelem = (size_t)PT_REGS_PARM1(ctx);
    size_t elsize = (size_t)PT_REGS_PARM2(ctx);
    printt("pymem_calloc nelem: %lu, elsize： %lu",nelem, elsize);
    return alloc_enter(ctx, nelem * elsize, PYCALLOC);
}

// void * PyMem_Calloc(size_t nelem, size_t elsize)
SEC("uretprobe/pymem_calloc")
int PyMem_Calloc_exit(struct pt_regs *ctx)
{
    printt("pymem_calloc exit： %d", 1);
    return alloc_exit2(ctx, PT_REGS_RC(ctx), PYCALLOC);
}

// void * PyMem_Realloc(void *ptr, size_t new_size)
SEC("uprobe/pymem_realloc")
int PyMem_Realloc_enter(struct pt_regs *ctx) {
    size_t size = (size_t)PT_REGS_PARM2(ctx);
    printt("pymem_realloc exit： %d", 1);
    alloc_enter(ctx, size, PYREALLOC);
    void *ptr = (void *)PT_REGS_PARM1(ctx);
    return free_entry(ctx, ptr);
}

// void * PyMem_Realloc(void *ptr, size_t new_size)
SEC("uretprobe/pymem_realloc")
int PyMem_Realloc_exit(struct pt_regs *ctx) {
    return alloc_exit(ctx, PYREALLOC);
}

// void PyMem_Free(void *ptr)
SEC("uprobe/pymem_free")
int PyMem_Free_enter(struct pt_regs *ctx) {
    void *address = (void *)PT_REGS_PARM1(ctx);
    return free_entry(ctx, address);
}



/** pymem_raw **/
// void * PyMem_RawMalloc(size_t size)
SEC("uprobe/py_malloc")
int Py_Malloc_enter(struct pt_regs *ctx)
{
    u32 tid = bpf_get_current_pid_tgid();
    u64 key_py_malloc = (u64)PYMALLOC << 32 | tid;
    u64* size64 = bpf_map_lookup_elem(&size_record, &key_py_malloc);
    if (size64)
        return 0;
    u64 key_py_calloc = (u64)PYCALLOC << 32 | tid;
    size64 = bpf_map_lookup_elem(&size_record, &key_py_calloc);
    if (size64)
        return 0;
    u64 key_py_realloc = (u64)PYREALLOC << 32 | tid;
    size64 = bpf_map_lookup_elem(&size_record, &key_py_realloc);
    if (size64)
        return 0;
    size_t nbytes = (size_t)PT_REGS_PARM1(ctx);
    return alloc_enter(ctx, nbytes, PYRAWMALLOC);
}

// // void * PyMem_RawMalloc(size_t size)
SEC("uretprobe/py_malloc")
int Py_Malloc_exit(struct pt_regs *ctx)
{
    return alloc_exit2(ctx, PT_REGS_RC(ctx), PYRAWMALLOC);
}

// void * PyMem_RawCalloc(size_t nelem, size_t elsize)
SEC("uprobe/py_calloc")
int Py_Calloc_enter(struct pt_regs *ctx)
{
    u32 tid = bpf_get_current_pid_tgid();
    u64 key_py_malloc = (u64)PYMALLOC << 32 | tid;
    u64* size64 = bpf_map_lookup_elem(&size_record, &key_py_malloc);
    if (size64)
        return 0;
    u64 key_py_calloc = (u64)PYCALLOC << 32 | tid;
    size64 = bpf_map_lookup_elem(&size_record, &key_py_calloc);
    if (size64)
        return 0;
    u64 key_py_realloc = (u64)PYREALLOC << 32 | tid;
    size64 = bpf_map_lookup_elem(&size_record, &key_py_realloc);
    if (size64)
        return 0;
    size_t nelem = (size_t)PT_REGS_PARM1(ctx);
    size_t elsize = (size_t)PT_REGS_PARM2(ctx);
    return alloc_enter(ctx, nelem * elsize, PYRAWCALLOC);
}

// void * PyMem_RawCalloc(size_t nelem, size_t elsize)
SEC("uretprobe/py_calloc")
int Py_Calloc_exit(struct pt_regs *ctx)
{
    return alloc_exit2(ctx, PT_REGS_RC(ctx), PYRAWCALLOC);
}

// void* PyMem_RawRealloc(void *ptr, size_t new_size)
SEC("uprobe/py_realloc")
int Py_Realloc_enter(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 key_py_malloc = (u64)PYMALLOC << 32 | tid;
    u64* size64 = bpf_map_lookup_elem(&size_record, &key_py_malloc);
    if (size64)
        return 0;
    u64 key_py_calloc = (u64)PYCALLOC << 32 | tid;
    size64 = bpf_map_lookup_elem(&size_record, &key_py_calloc);
    if (size64)
        return 0;
    u64 key_py_realloc = (u64)PYREALLOC << 32 | tid;
    size64 = bpf_map_lookup_elem(&size_record, &key_py_realloc);
    if (size64)
        return 0;
    void *ptr = (void *)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM2(ctx);
    alloc_enter(ctx, size, PYRAWREALLOC);
    return free_entry(ctx, ptr);
}

// void* PyMem_RawRealloc(void *ptr, size_t new_size)
SEC("uretprobe/py_realloc")
int Py_Realloc_exit(struct pt_regs *ctx) {
    return alloc_exit(ctx, PYRAWREALLOC);
}

// void PyMem_RawFree(void *ptr)
SEC("uprobe/py_free")
int Py_Free_enter(struct pt_regs *ctx) {
    void *address = (void *)PT_REGS_PARM1(ctx);
    return free_entry(ctx, address);
}


/** rust **/