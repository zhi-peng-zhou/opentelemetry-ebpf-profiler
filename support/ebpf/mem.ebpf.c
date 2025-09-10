#include "bpfdefs.h"
#include "frametypes.h"
#include "stackdeltatypes.h"
#include "tracemgmt.h"
#include "types.h"
#include "tsd.h"

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

typedef struct {
    u64 size;
    u64 stack_id;
    u64 timestamp_ns;
} alloc_info_t;

bpf_map_def SEC("maps") stack_traces = {
  .type        = BPF_MAP_TYPE_STACK_TRACE,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(u64) * 16,
  .max_entries = 16 * 1024,
};

bpf_map_def SEC("maps") size_record = {
  .type        = BPF_MAP_TYPE_HASH,
  .key_size    = sizeof(u64),
  .value_size  = sizeof(u64),
  .max_entries = 1000000,
};

//bpf_map_def SEC("maps") comvined_alloc_infos = {
//  .type        = BPF_MAP_TYPE_HASH,
//  .key_size    = sizeof(u64),
//  .value_size  = sizeof(combined_alloc_info_t),
//  .max_entries = 1000000,
//};

bpf_map_def SEC("maps") alloc_infos = {
  .type        = BPF_MAP_TYPE_HASH,
  .key_size    = sizeof(u64),
  .value_size  = sizeof(alloc_info_t),
  .max_entries = 1000000,
};

bpf_map_def SEC("maps") memptrs = {
  .type        = BPF_MAP_TYPE_HASH,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(u64),
  .max_entries = 1000000,
};

//bpf_map_def SEC("maps") events = {
//  .type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
//  .key_size    = sizeof(int),
//  .value_size  = 0,
//  .max_entries = 0,
//};


//static inline int update_statistics_add(u64 stack_id, u64 sz) {
//    combined_alloc_info_t *existing_cinfo;
//    combined_alloc_info_t cinfo = {0, 0};
//
//    existing_cinfo = bpf_map_lookup_elem(&comvined_alloc_infos, &stack_id);
//    if (!existing_cinfo) {
//        bpf_map_update_elem(&comvined_alloc_infos, &stack_id, &cinfo, BPF_ANY);
//        existing_cinfo = bpf_map_lookup_elem(&comvined_alloc_infos, &stack_id);
//        if (!existing_cinfo)
//                return 0;
//    }
//    __sync_fetch_and_add(&existing_cinfo->total_size, sz);
//    __sync_fetch_and_add(&existing_cinfo->mem_allocs, 1);
//    return 0;
//}
//
//static inline void update_statistics_del(u64 stack_id, u64 sz) {
//    combined_alloc_info_t *existing_cinfo;
//    existing_cinfo = bpf_map_lookup_elem(&comvined_alloc_infos, &stack_id);
//    if (!existing_cinfo)
//        return;
//
//    if (existing_cinfo->mem_allocs > 1) {
//        __sync_fetch_and_sub(&existing_cinfo->total_size, sz);
//        __sync_fetch_and_sub(&existing_cinfo->mem_allocs, 1);
//    } else {
//        bpf_map_delete_elem(&comvined_alloc_infos, &stack_id);
//    }
//}


static inline int alloc_enter(struct pt_regs *ctx, size_t size, u32 type_index) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 s = size;
    u64 key = (u64)type_index << 32 | tid;
    bpf_map_update_elem(&size_record, &key, &s, BPF_ANY);
//    printt("alloc_enter: key: %llu, size: %llu", key, s);
    return 0;
}



static inline int alloc_exit2(struct pt_regs *ctx, u64 address, u32 type_index) {
    u64 id  = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id & 0xFFFFFFFF;
    u64 key = (u64)type_index << 32 | tid;
    u64* size64 = bpf_map_lookup_elem(&size_record, &key);
    printt("alloc_exit2：key: %llu", key);
    if (!size64)
//        printt("alloc_exit2 return：key: %llu", key);
        return 0; // missed alloc entry

    bpf_map_delete_elem(&size_record, &key);
    event e = {};
    e.size = *size64;
    e.pid = pid;
    e.type_t = 1;
    if (address == 0)
        return 0;
    u64 ts = bpf_ktime_get_ns();

    e.timestamp_ns = ts;
    u32 stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK | BPF_F_REUSE_STACKID);
    if (stack_id < 0)
        return 0;
    e.stack_id = stack_id;
//    update_statistics_add(stack_id, *size64);
    alloc_info_t ai = {*size64, stack_id, bpf_ktime_get_ns()};
    bpf_map_update_elem(&alloc_infos, &address, &ai, BPF_ANY);
//    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return collect_trace(ctx, TRACE_HEAP_ALLOC, pid, tid, ts, 0, (int)*size64);
//    return 0;
}

static inline int alloc_exit(struct pt_regs *ctx, u32 type_index) {
        return alloc_exit2(ctx, PT_REGS_RC(ctx), type_index);
}


static inline int free_enter(struct pt_regs *ctx, void *address) {
    u64 id  = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id & 0xFFFFFFFF;
    u64 addr = (u64)address;
//    DEBUG_PRINT("free_enter %%llu",addr);
    alloc_info_t *info = bpf_map_lookup_elem(&alloc_infos, &addr);
    if (!info)
        return 0;
//    DEBUG_PRINT("free_enter %p",addr);
    bpf_map_delete_elem(&alloc_infos, &addr);
//    update_statistics_del(info->stack_id, info->size);
//    u32 pid = bpf_get_current_pid_tgid() >> 32;

    event e = {};
    e.size = info->size;
    e.pid = pid;
    e.type_t = 0;
    e.stack_id = info->stack_id;
    u64 ts = bpf_ktime_get_ns();
    e.timestamp_ns = ts;
//    int i_size = 0 - (int)*size64);
    return collect_trace(ctx, TRACE_HEAP_ALLOC, pid, tid, ts, 0, -info->size);
//    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
//    return 0;
}


SEC("uprobe/malloc")
int malloc_enter(struct pt_regs *ctx, size_t size) {
    size_t actual_size = (size_t)PT_REGS_PARM1(ctx);
    return alloc_enter(ctx, actual_size, MALLOC);
}

SEC("uretprobe/malloc")
int malloc_exit(struct pt_regs *ctx) {
    printt("alloc_exit2：key: %d", 1);
    return alloc_exit2(ctx, PT_REGS_RC(ctx), MALLOC);
}

SEC("uprobe/free")
int ufree_enter(struct pt_regs *ctx) {
    void *address = (void *)PT_REGS_PARM1(ctx);
    return free_enter(ctx, address);
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
    free_enter(ctx, ptr);
    return alloc_enter(ctx, size, REALLOC);
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
    return free_enter(ctx, address);
}
SEC("uprobe/posix_memalign")
int posix_memalign_enter(struct pt_regs *ctx) {
    void ** memptr = (void **)PT_REGS_PARM1(ctx);
//    size_t alignment = (size_t)PT_REGS_PARM2(ctx);
    size_t size = (size_t)PT_REGS_PARM3(ctx);

    u64 memptr64 = (u64)(size_t)memptr;
    u32 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&memptrs, &tid, &memptr64,BPF_ANY);
    return alloc_enter(ctx, size, POSIX_MEMALIGN);
}
SEC("uretprobe/posix_memalign")
int posix_memalign_exit(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
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


SEC("tracepoint/kmem/kfree")
int kfree(struct kfree_event *info)
{
    return free_enter((struct pt_regs *)info, (void *)info->ptr);
}

SEC("tracepoint/kmem/kmalloc")
int kmalloc(struct kmalloc_event *info)
{
    alloc_enter((struct pt_regs *)info, info-> bytes_alloc, MALLOC);
    return alloc_exit2((struct pt_regs *)info, (u64)info->ptr, MALLOC);
}

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

















//char _license[] SEC("license") = "GPL";
//// this number will be interpreted by the elf loader
//// to set the current running kernel version
//u32 _version SEC("version")    = 0xFFFFFFFE;