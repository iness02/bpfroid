// +build ignore
// ^^ this is a golang build tag meant to exclude this C file from compilation by the CGO compiler

/* In Linux 5.4 asm_inline was introduced, but it's not supported by clang.
 * Redefine it to just asm to enable successful compilation.
 * see https://github.com/iovisor/bcc/commit/2d1497cde1cc9835f759a707b42dea83bee378b8 for more details
 */
#include <linux/types.h>
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>
#include <uapi/linux/uio.h>
#include <uapi/linux/un.h>
#include <uapi/linux/utsname.h>
#include <linux/binfmts.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/pid_namespace.h>
#include <linux/security.h>
#include <linux/socket.h>
#include <linux/version.h>

#include <uapi/linux/bpf.h>
#include <linux/kconfig.h>
#include <linux/version.h>

#undef container_of
//#include "bpf_core_read.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#if defined(bpf_target_x86)
#define PT_REGS_PARM6(ctx)  ((ctx)->r9)
#elif defined(bpf_target_arm64)
#define PT_REGS_PARM6(x) (((PT_REGS_ARM64 *)(x))->regs[5])
#endif

#define MAX_PERCPU_BUFSIZE  (1 << 15)     // This value is actually set by the kernel as an upper bound
#define MAX_STRING_SIZE     4096          // Choosing this value to be the same as PATH_MAX
#define MAX_STR_ARR_ELEM    40            // String array elements number should be bounded due to instructions limit
#define MAX_PATH_PREF_SIZE  50            // Max path prefix should be bounded due to instructions limit
#define MAX_STACK_ADDRESSES 1024          // Max amount of different stack trace addresses to buffer in the Map
#define MAX_STACK_DEPTH     20            // Max depth of each stack trace to track
#define MAX_STR_FILTER_SIZE 16            // Max string filter size should be bounded to the size of the compared values (comm, uts)

#define SUBMIT_BUF_IDX      0
#define STRING_BUF_IDX      1
#define FILE_BUF_IDX        2
#define MAX_BUFFERS         3

#define SEND_VFS_WRITE      1
#define SEND_MPROTECT       2
#define SEND_META_SIZE      20

#define ALERT_MMAP_W_X      1
#define ALERT_MPROT_X_ADD   2
#define ALERT_MPROT_W_ADD   3
#define ALERT_MPROT_W_REM   4

#define TAIL_VFS_WRITE      0
#define TAIL_VFS_WRITEV     1
#define TAIL_SEND_BIN       2
#define MAX_TAIL_CALL       3

#define NONE_T        0UL
#define INT_T         1UL
#define UINT_T        2UL
#define LONG_T        3UL
#define ULONG_T       4UL
#define OFF_T_T       5UL
#define MODE_T_T      6UL
#define DEV_T_T       7UL
#define SIZE_T_T      8UL
#define POINTER_T     9UL
#define STR_T         10UL
#define STR_ARR_T     11UL
#define SOCKADDR_T    12UL
#define ALERT_T       13UL
#define TYPE_MAX      255UL

#define TAG_NONE           0UL

#if defined(bpf_target_x86)
#define SYS_OPEN              2
#define SYS_MMAP              9
#define SYS_MPROTECT          10
#define SYS_RT_SIGRETURN      15
#define SYS_CLONE             56
#define SYS_FORK              57
#define SYS_VFORK             58
#define SYS_EXECVE            59
#define SYS_EXIT              60
#define SYS_EXIT_GROUP        231
#define SYS_OPENAT            257
#define SYS_EXECVEAT          322
#elif defined(bpf_target_arm64)
#define SYS_OPEN              1000 // undefined in arm64
#define SYS_MMAP              222
#define SYS_MPROTECT          226
#define SYS_RT_SIGRETURN      139
#define SYS_CLONE             220
#define SYS_FORK              1000 // undefined in arm64
#define SYS_VFORK             1000 // undefined in arm64
#define SYS_EXECVE            221
#define SYS_EXIT              93
#define SYS_EXIT_GROUP        94
#define SYS_OPENAT            56
#define SYS_EXECVEAT          281
#endif

#define RAW_SYS_ENTER         1000
#define RAW_SYS_EXIT          1001
#define DO_EXIT               1002
#define CAP_CAPABLE           1003
#define SECURITY_BPRM_CHECK   1004
#define SECURITY_FILE_OPEN    1005
#define SECURITY_INODE_UNLINK 1006
#define VFS_WRITE             1007
#define VFS_WRITEV            1008
#define MEM_PROT_ALERT        1009
#define SCHED_PROCESS_EXIT    1010
#define GENERIC_UPROBE        1011
#define GENERIC_API_UPROBE    1012
#define UID_CHANGE_ALERT      1013
#define WRITE_ALERT           1014
#define IP_CHANGE_ALERT       1015
#define SELINUX_MODE_CHANGE_ALERT 1016
#define SELINUX_POLICY_RELOAD_ALERT 1017
#define SELINUX_PROTECTED_RESOURCE_ACCESS_ALERT 1018
#define SELINUX_DENIAL        1019
#define SELINUX_REPEATED_DENIAL_ALERT 1020
#define SU_SUDO_ALERT         1021
#define MAX_EVENT_ID          1022

// IP change action types
#define IP_ACTION_ADD         1
#define IP_ACTION_DEL         2

// SELinux mode values (success)
#define SELINUX_MODE_PERMISSIVE 0
#define SELINUX_MODE_ENFORCING  1
// SELinux mode values (attempt/failed)
#define SELINUX_ATTEMPT_PERMISSIVE 2
#define SELINUX_ATTEMPT_ENFORCING  3
// SELinux open attempt (write intent detected at open time)
#define SELINUX_OPEN_ATTEMPT       4

// SELinux change method
#define SELINUX_METHOD_WRITE      1
#define SELINUX_METHOD_SETENFORCE 2

// SELinux policy reload action types
#define SELINUX_POLICY_RELOAD_SUCCESS     1  // Policy successfully loaded
#define SELINUX_POLICY_RELOAD_ATTEMPT     2  // Write attempt (may have failed)
#define SELINUX_POLICY_OPEN_DENIED        3  // Open attempt denied (permission error)

#define CONFIG_SHOW_SYSCALL         1
#define CONFIG_EXEC_ENV             2
#define CONFIG_CAPTURE_FILES        3
#define CONFIG_EXTRACT_DYN_CODE     4
#define CONFIG_TRACEE_PID           5
#define CONFIG_CAPTURE_STACK_TRACES 6
#define CONFIG_UID_FILTER           7
#define CONFIG_MNT_NS_FILTER        8
#define CONFIG_PID_NS_FILTER        9
#define CONFIG_UTS_NS_FILTER        10
#define CONFIG_COMM_FILTER          11
#define CONFIG_PID_FILTER           12
#define CONFIG_CONT_FILTER          13
#define CONFIG_FOLLOW_FILTER        14
#define CONFIG_NEW_PID_FILTER       15
#define CONFIG_NEW_CONT_FILTER      16

// get_config(CONFIG_XXX_FILTER) returns 0 if not enabled
#define FILTER_IN  1
#define FILTER_OUT 2

#define UID_LESS      0
#define UID_GREATER   1
#define PID_LESS      2
#define PID_GREATER   3
#define MNTNS_LESS    4
#define MNTNS_GREATER 5
#define PIDNS_LESS    6
#define PIDNS_GREATER 7

#define LESS_NOT_SET    0
#define GREATER_NOT_SET ULLONG_MAX

#define DEV_NULL_STR    0

#define READ_KERN(ptr) ({ typeof(ptr) _val;                             \
                          __builtin_memset(&_val, 0, sizeof(_val));     \
                          bpf_probe_read(&_val, sizeof(_val), &ptr);    \
                          _val;                                         \
                        })

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries) \
struct bpf_map_def SEC("maps") _name = { \
  .type = _type, \
  .key_size = sizeof(_key_type), \
  .value_size = sizeof(_value_type), \
  .max_entries = _max_entries, \
};

#define BPF_HASH(_name, _key_type, _value_type) \
BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, 10240);

#define BPF_ARRAY(_name, _value_type, _max_entries) \
BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, u32, _value_type, _max_entries);

#define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries) \
BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, _value_type, _max_entries);

#define BPF_PROG_ARRAY(_name, _max_entries) \
BPF_MAP(_name, BPF_MAP_TYPE_PROG_ARRAY, u32, u32, _max_entries);

#define BPF_PERF_OUTPUT(_name) \
BPF_MAP(_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, __u32, 1024);

// Stack Traces are slightly different
// in that the value is 1 big byte array
// of the stack addresses
#define BPF_STACK_TRACE(_name, _max_entries) \
struct bpf_map_def SEC("maps") _name = { \
  .type = BPF_MAP_TYPE_STACK_TRACE, \
  .key_size = sizeof(u32), \
  .value_size = sizeof(size_t) * MAX_STACK_DEPTH, \
  .max_entries = _max_entries, \
};

#ifdef RHEL_RELEASE_CODE
#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 0))
#define RHEL_RELEASE_GT_8_0
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
#error Minimal required kernel version is 4.9
#endif

/*=============================== INTERNAL STRUCTS ===========================*/

typedef struct context {
    u64 ts;                     // Timestamp
    u32 pid;                    // PID as in the userspace term
    u32 tid;                    // TID as in the userspace term
    u32 ppid;                   // Parent PID as in the userspace term
    u32 host_pid;               // PID in host pid namespace
    u32 host_tid;               // TID in host pid namespace
    u32 host_ppid;              // Parent PID in host pid namespace
    u32 uid;
    u32 mnt_id;
    u32 pid_id;
    char comm[TASK_COMM_LEN];
    char uts_name[TASK_COMM_LEN];
    u32 eventid;
    s64 retval;
    u32 stack_id;
    u8 argnum;
} context_t;

typedef struct args {
    unsigned long args[6];
} args_t;

typedef struct bin_args {
    u8 type;
    u8 metadata[SEND_META_SIZE];
    char *ptr;
    loff_t start_off;
    unsigned int full_size;
    u8 iov_idx;
    u8 iov_len;
    struct iovec *vec;
} bin_args_t;

typedef struct simple_buf {
    u8 buf[MAX_PERCPU_BUFSIZE];
} buf_t;

typedef struct path_filter {
    char path[MAX_PATH_PREF_SIZE];
} path_filter_t;

typedef struct string_filter {
    char str[MAX_STR_FILTER_SIZE];
} string_filter_t;

typedef struct alert {
    u64 ts;     // Timestamp
    u32 msg;    // Encoded message
    u8 payload; // Non zero if payload is sent to userspace
} alert_t;

/*================================ KERNEL STRUCTS =============================*/

struct mnt_namespace {
    atomic_t        count;
    struct ns_common    ns;
    // ...
};

struct uts_namespace {
    struct kref kref;
    struct new_utsname name;
    // ...
};

struct mount {
    struct hlist_node mnt_hash;
    struct mount *mnt_parent;
    struct dentry *mnt_mountpoint;
    struct vfsmount mnt;
    // ...
};

// Simplified struct definitions for IP address change detection
// Note: These are partial definitions to extract the fields we need
struct net_device {
    char name[16];    // IFNAMSIZ = 16
    // ... other fields not needed
};

struct in_device {
    struct net_device *dev;
    // ... other fields not needed
};

// rcu_head is 16 bytes (two pointers) on 64-bit systems
struct rcu_head_compat {
    void *next;
    void *func;
};

struct in_ifaddr {
    struct hlist_node hash;          // 16 bytes (two pointers)
    struct in_ifaddr *ifa_next;      // 8 bytes
    struct in_device *ifa_dev;       // 8 bytes
    struct rcu_head_compat rcu_head; // 16 bytes (NOT 8!)
    __be32 ifa_local;
    __be32 ifa_address;
    __be32 ifa_mask;
    __u32 ifa_rt_priority;
    __be32 ifa_broadcast;
    unsigned char ifa_scope;
    unsigned char ifa_prefixlen;
    __u32 ifa_flags;
    char ifa_label[16];          // IFNAMSIZ = 16
    // ... other fields not needed
};

/*=================================== MAPS =====================================*/

BPF_HASH(config_map, u32, u32);                         // Various configurations
BPF_HASH(chosen_events_map, u32, u32);                  // Events chosen by the user
BPF_HASH(traced_pids_map, u32, u32);                    // Keep track of traced pids
BPF_HASH(new_pids_map, u32, u32);                       // Keep track of the processes of newly executed binaries
BPF_HASH(new_pidns_map, u32, u32);                      // Keep track of new pid namespaces
BPF_HASH(args_map, u64, args_t);                        // Persist args info between function entry and return
BPF_HASH(ret_map, u64, u64);                            // Persist return value to be used in tail calls
BPF_HASH(inequality_filter, u32, u64);                  // Used to filter events by some uint field either by < or >
BPF_HASH(uid_filter, u32, u32);                         // Used to filter events by UID, for specific UIDs either by == or !=
BPF_HASH(pid_filter, u32, u32);                         // Used to filter events by PID
BPF_HASH(mnt_ns_filter, u64, u32);                      // Used to filter events by mount namespace id
BPF_HASH(pid_ns_filter, u64, u32);                      // Used to filter events by pid namespace id
BPF_HASH(uts_ns_filter, string_filter_t, u32);          // Used to filter events by uts namespace name
BPF_HASH(comm_filter, string_filter_t, u32);            // Used to filter events by command name
BPF_HASH(bin_args_map, u64, bin_args_t);                // Persist args for send_bin funtion
BPF_HASH(sys_32_to_64_map, u32, u32);                   // Map 32bit syscalls numbers to 64bit syscalls numbers
BPF_HASH(params_types_map, u32, u64);                   // Encoded parameters types for event
BPF_HASH(params_names_map, u32, u64);                   // Encoded parameters names for event
BPF_ARRAY(file_filter, path_filter_t, 3);               // Used to filter vfs_write events
BPF_ARRAY(string_store, path_filter_t, 1);              // Store strings from userspace
BPF_PERCPU_ARRAY(bufs, buf_t, MAX_BUFFERS);             // Percpu global buffer variables
BPF_PERCPU_ARRAY(bufs_off, u32, MAX_BUFFERS);           // Holds offsets to bufs respectively
BPF_PROG_ARRAY(prog_array, MAX_TAIL_CALL);              // Used to store programs for tail calls
BPF_PROG_ARRAY(sys_enter_tails, MAX_EVENT_ID);          // Used to store programs for tail calls
BPF_PROG_ARRAY(sys_exit_tails, MAX_EVENT_ID);           // Used to store programs for tail calls
BPF_STACK_TRACE(stack_addresses, MAX_STACK_ADDRESSES);  // Used to store stack traces

BPF_HASH(types_map, u64, u64);                      // Argument types of generic event handlers
BPF_HASH(uprobe_off_map, u64, u64);                 // Save uprobe offset to be used in uretprobe

BPF_HASH(pid_to_uid, u32, u32);                     // pid to uid map

/*================================== EVENTS ====================================*/

BPF_PERF_OUTPUT(events);                            // Events submission
BPF_PERF_OUTPUT(file_writes);                       // File writes events submission

/*================== KERNEL VERSION DEPENDANT HELPER FUNCTIONS =================*/

static __always_inline u32 get_task_mnt_ns_id(struct task_struct *task)
{
    return READ_KERN(READ_KERN(READ_KERN(task->nsproxy)->mnt_ns)->ns.inum);
}

static __always_inline u32 get_task_pid_ns_id(struct task_struct *task)
{
    return READ_KERN(READ_KERN(READ_KERN(task->nsproxy)->pid_ns_for_children)->ns.inum);
}

static __always_inline u32 get_task_ns_pid(struct task_struct *task)
{
    unsigned int level = READ_KERN(READ_KERN(READ_KERN(task->nsproxy)->pid_ns_for_children)->level);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(RHEL_RELEASE_GT_8_0))
    // kernel 4.14-4.18:
    return READ_KERN(READ_KERN(task->pids[PIDTYPE_PID].pid)->numbers[level].nr);
#else
    // kernel 4.19 onwards:
    return READ_KERN(READ_KERN(task->thread_pid)->numbers[level].nr);
#endif
}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task)
{
    unsigned int level = READ_KERN(READ_KERN(READ_KERN(task->nsproxy)->pid_ns_for_children)->level);
    struct task_struct *group_leader = READ_KERN(task->group_leader);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(RHEL_RELEASE_GT_8_0))
    // kernel 4.14-4.18:
    return READ_KERN(READ_KERN(group_leader->pids[PIDTYPE_PID].pid)->numbers[level].nr);
#else
    // kernel 4.19 onwards:
    return READ_KERN(READ_KERN(group_leader->thread_pid)->numbers[level].nr);
#endif
}

static __always_inline u32 get_task_ns_ppid(struct task_struct *task)
{
    struct task_struct *real_parent = READ_KERN(task->real_parent);
    unsigned int level = READ_KERN(READ_KERN(READ_KERN(real_parent->nsproxy)->pid_ns_for_children)->level);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(RHEL_RELEASE_GT_8_0))
    // kernel 4.14-4.18:
    return READ_KERN(READ_KERN(real_parent->pids[PIDTYPE_PID].pid)->numbers[level].nr);
#else
    // kernel 4.19 onwards:
    return READ_KERN(READ_KERN(real_parent->thread_pid)->numbers[level].nr);
#endif
}

static __always_inline char * get_task_uts_name(struct task_struct *task)
{
    return READ_KERN(READ_KERN(READ_KERN(task->nsproxy)->uts_ns)->name.nodename);
}

static __always_inline u32 get_task_ppid(struct task_struct *task)
{
    return READ_KERN(READ_KERN(task->real_parent)->pid);
}

static __always_inline bool is_x86_compat(struct task_struct *task)
{
#if defined(bpf_target_x86)
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 18))
    return READ_KERN(task->thread.status) & TS_COMPAT;
#else
    return READ_KERN(task->thread_info.status) & TS_COMPAT;
#endif
#else
    return false;
#endif
}

static __always_inline bool is_arm64_compat(struct task_struct *task)
{
#if defined(bpf_target_arm64)
    return READ_KERN(task->thread_info.flags) & _TIF_32BIT;
#else
    return false;
#endif
}

static __always_inline bool is_compat(struct task_struct *task)
{
#if defined(bpf_target_x86)
    return is_x86_compat(task);
#elif defined(bpf_target_arm64)
    return is_arm64_compat(task);
#else
    return false;
#endif
}

static __always_inline int get_syscall_id_from_regs(struct pt_regs *regs)
{
#if defined(bpf_target_x86)
    int id = READ_KERN(regs->orig_ax);
#elif defined(bpf_target_arm64)
    int id = READ_KERN(regs->syscallno);
#endif
    return id;
}

#if defined(bpf_target_x86)
static __always_inline struct pt_regs* get_task_pt_regs(struct task_struct *task)
{
    void* __ptr = READ_KERN(task->stack) + THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;
    return ((struct pt_regs *)__ptr) - 1;
}
#endif

static __always_inline int get_syscall_ev_id_from_regs()
{
#if defined(bpf_target_x86)
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct pt_regs *real_ctx = get_task_pt_regs(task);
    int syscall_nr = READ_KERN(real_ctx->orig_ax);

    if (is_x86_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls (which also represent the event ids)
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &syscall_nr);
        if (id_64 == 0)
            return -1;

        syscall_nr = *id_64;
    }

    return syscall_nr;
#else
    return 0;
#endif
}

static __always_inline struct dentry* get_mnt_root_ptr_from_vfsmnt(struct vfsmount *vfsmnt)
{
    return READ_KERN(vfsmnt->mnt_root);
}

static __always_inline struct dentry* get_d_parent_ptr_from_dentry(struct dentry *dentry)
{
    return READ_KERN(dentry->d_parent);
}

static __always_inline struct qstr get_d_name_from_dentry(struct dentry *dentry)
{
    return READ_KERN(dentry->d_name);
}

static __always_inline struct file* get_file_ptr_from_bprm(struct linux_binprm *bprm)
{
    return READ_KERN(bprm->file);
}

static __always_inline dev_t get_dev_from_file(struct file *file)
{
    return READ_KERN(READ_KERN(READ_KERN(file->f_inode)->i_sb)->s_dev);
}

static __always_inline unsigned long get_inode_nr_from_file(struct file *file)
{
    return READ_KERN(READ_KERN(file->f_inode)->i_ino);
}

static __always_inline const char* get_fs_type_from_file(struct file *file)
{
    return READ_KERN(READ_KERN(READ_KERN(READ_KERN(file->f_inode)->i_sb)->s_type)->name);
}

static __always_inline unsigned short get_inode_mode_from_file(struct file *file)
{
    return READ_KERN(READ_KERN(file->f_inode)->i_mode);
}

static __always_inline struct path get_path_from_file(struct file *file)
{
    return READ_KERN(file->f_path);
}

static __always_inline unsigned long get_vma_flags(struct vm_area_struct *vma)
{
    return READ_KERN(vma->vm_flags);
}

static inline struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
}

/*============================== HELPER FUNCTIONS ==============================*/

static __always_inline u64 get_handler_types(u64 key)
{
    u64 *types = bpf_map_lookup_elem(&types_map, &key);

    if (types == NULL)
        return 0;

    return *types;
}

static __inline int has_prefix(char *prefix_p, char *str_p, int n)
{
    char prefix_arr[MAX_PATH_PREF_SIZE+1];
    char str_arr[MAX_PATH_PREF_SIZE+1];

    prefix_arr[MAX_PATH_PREF_SIZE] = 0;
    str_arr[MAX_PATH_PREF_SIZE] = 0;
    bpf_probe_read(prefix_arr, MAX_PATH_PREF_SIZE, prefix_p);
    bpf_probe_read(str_arr, MAX_PATH_PREF_SIZE, str_p);

    char *prefix = prefix_arr;
    char *str = str_arr;

    int i;
    #pragma unroll
    for (i = 0; i < n; prefix++, str++, i++) {
        if (!*prefix)
            return 1;
        if (*prefix != *str) {
            return 0;
        }
    }

    // prefix is too long
    return 0;
}

// Check if the path matches /sys/fs/selinux/enforce
// Using direct character comparison to avoid BPF rodata relocation issues
static __always_inline int is_selinux_enforce_path(char *path_p)
{
    char path[32];
    bpf_probe_read_str(path, sizeof(path), path_p);
    
    // Compare with "/sys/fs/selinux/enforce" character by character
    if (path[0] != '/' || path[1] != 's' || path[2] != 'y' || path[3] != 's' ||
        path[4] != '/' || path[5] != 'f' || path[6] != 's' || path[7] != '/' ||
        path[8] != 's' || path[9] != 'e' || path[10] != 'l' || path[11] != 'i' ||
        path[12] != 'n' || path[13] != 'u' || path[14] != 'x' || path[15] != '/' ||
        path[16] != 'e' || path[17] != 'n' || path[18] != 'f' || path[19] != 'o' ||
        path[20] != 'r' || path[21] != 'c' || path[22] != 'e' || path[23] != '\0')
        return 0;
    
    return 1;
}

// Check if the path matches /sys/fs/selinux/load
// This file is used to load new SELinux policies
// Using direct character comparison to avoid BPF rodata relocation issues
static __always_inline int is_selinux_load_path(char *path_p)
{
    char path[32];
    bpf_probe_read_str(path, sizeof(path), path_p);
    
    // Compare with "/sys/fs/selinux/load" character by character (20 chars + null)
    // /sys/fs/selinux/load
    if (path[0] != '/' || path[1] != 's' || path[2] != 'y' || path[3] != 's' ||
        path[4] != '/' || path[5] != 'f' || path[6] != 's' || path[7] != '/' ||
        path[8] != 's' || path[9] != 'e' || path[10] != 'l' || path[11] != 'i' ||
        path[12] != 'n' || path[13] != 'u' || path[14] != 'x' || path[15] != '/' ||
        path[16] != 'l' || path[17] != 'o' || path[18] != 'a' || path[19] != 'd' ||
        path[20] != '\0')
        return 0;
    
    return 1;
}

// Check if the path is a setenforce command
// Common paths: /system/bin/setenforce, /sbin/setenforce
// Using direct character comparison to avoid BPF rodata relocation issues
static __always_inline int is_setenforce_cmd(char *path_p)
{
    char path[64];
    bpf_probe_read_str(path, sizeof(path), path_p);
    
    // Check for /system/bin/setenforce (Android) - 23 chars
    // "/system/bin/setenforce"
    if (path[0] == '/' && path[1] == 's' && path[2] == 'y' && path[3] == 's' &&
        path[4] == 't' && path[5] == 'e' && path[6] == 'm' && path[7] == '/' &&
        path[8] == 'b' && path[9] == 'i' && path[10] == 'n' && path[11] == '/' &&
        path[12] == 's' && path[13] == 'e' && path[14] == 't' && path[15] == 'e' &&
        path[16] == 'n' && path[17] == 'f' && path[18] == 'o' && path[19] == 'r' &&
        path[20] == 'c' && path[21] == 'e' && path[22] == '\0')
        return 1;
    
    // Check for /sbin/setenforce (Linux) - 17 chars
    // "/sbin/setenforce"
    if (path[0] == '/' && path[1] == 's' && path[2] == 'b' && path[3] == 'i' &&
        path[4] == 'n' && path[5] == '/' && path[6] == 's' && path[7] == 'e' &&
        path[8] == 't' && path[9] == 'e' && path[10] == 'n' && path[11] == 'f' &&
        path[12] == 'o' && path[13] == 'r' && path[14] == 'c' && path[15] == 'e' &&
        path[16] == '\0')
        return 1;
    
    // Check for /usr/sbin/setenforce (Linux) - 21 chars
    // "/usr/sbin/setenforce"
    if (path[0] == '/' && path[1] == 'u' && path[2] == 's' && path[3] == 'r' &&
        path[4] == '/' && path[5] == 's' && path[6] == 'b' && path[7] == 'i' &&
        path[8] == 'n' && path[9] == '/' && path[10] == 's' && path[11] == 'e' &&
        path[12] == 't' && path[13] == 'e' && path[14] == 'n' && path[15] == 'f' &&
        path[16] == 'o' && path[17] == 'r' && path[18] == 'c' && path[19] == 'e' &&
        path[20] == '\0')
        return 1;
    
    return 0;
}

// Check if the path is a su or sudo command
// Supports full path matching and basename matching
// Returns: 1 for su, 2 for sudo, 0 if not matched
static __always_inline int is_su_sudo_cmd(char *path_p)
{
    char path[64];
    int len = bpf_probe_read_str(path, sizeof(path), path_p);
    if (len <= 0)
        return 0;
    
    // Find the last '/' to get basename
    int last_slash = -1;
    #pragma unroll
    for (int i = 0; i < 63 && path[i] != '\0'; i++) {
        if (path[i] == '/')
            last_slash = i;
    }
    
    // Check basename "su" (exactly 2 chars after last slash, then null)
    // basename starts at last_slash + 1
    if (last_slash >= 0 && last_slash < 61) {
        int base = last_slash + 1;
        // Check for "su\0"
        if (path[base] == 's' && path[base+1] == 'u' && path[base+2] == '\0')
            return 1;
        // Check for "sudo\0"
        if (path[base] == 's' && path[base+1] == 'u' && path[base+2] == 'd' && 
            path[base+3] == 'o' && path[base+4] == '\0')
            return 2;
    }
    
    // Also check if path itself is just "su" or "sudo" (no leading slash)
    if (path[0] == 's' && path[1] == 'u' && path[2] == '\0')
        return 1;
    if (path[0] == 's' && path[1] == 'u' && path[2] == 'd' && path[3] == 'o' && path[4] == '\0')
        return 2;
    
    // Full path matching for common su locations
    // /system/bin/su
    if (path[0] == '/' && path[1] == 's' && path[2] == 'y' && path[3] == 's' &&
        path[4] == 't' && path[5] == 'e' && path[6] == 'm' && path[7] == '/' &&
        path[8] == 'b' && path[9] == 'i' && path[10] == 'n' && path[11] == '/' &&
        path[12] == 's' && path[13] == 'u' && path[14] == '\0')
        return 1;
    
    // /system/xbin/su
    if (path[0] == '/' && path[1] == 's' && path[2] == 'y' && path[3] == 's' &&
        path[4] == 't' && path[5] == 'e' && path[6] == 'm' && path[7] == '/' &&
        path[8] == 'x' && path[9] == 'b' && path[10] == 'i' && path[11] == 'n' &&
        path[12] == '/' && path[13] == 's' && path[14] == 'u' && path[15] == '\0')
        return 1;
    
    // /vendor/bin/su
    if (path[0] == '/' && path[1] == 'v' && path[2] == 'e' && path[3] == 'n' &&
        path[4] == 'd' && path[5] == 'o' && path[6] == 'r' && path[7] == '/' &&
        path[8] == 'b' && path[9] == 'i' && path[10] == 'n' && path[11] == '/' &&
        path[12] == 's' && path[13] == 'u' && path[14] == '\0')
        return 1;
    
    // /sbin/su
    if (path[0] == '/' && path[1] == 's' && path[2] == 'b' && path[3] == 'i' &&
        path[4] == 'n' && path[5] == '/' && path[6] == 's' && path[7] == 'u' &&
        path[8] == '\0')
        return 1;
    
    // /bin/su
    if (path[0] == '/' && path[1] == 'b' && path[2] == 'i' && path[3] == 'n' &&
        path[4] == '/' && path[5] == 's' && path[6] == 'u' && path[7] == '\0')
        return 1;
    
    // /su/bin/su (SuperSU/Magisk)
    if (path[0] == '/' && path[1] == 's' && path[2] == 'u' && path[3] == '/' &&
        path[4] == 'b' && path[5] == 'i' && path[6] == 'n' && path[7] == '/' &&
        path[8] == 's' && path[9] == 'u' && path[10] == '\0')
        return 1;
    
    // /data/adb/magisk/su (Magisk)
    if (path[0] == '/' && path[1] == 'd' && path[2] == 'a' && path[3] == 't' &&
        path[4] == 'a' && path[5] == '/' && path[6] == 'a' && path[7] == 'd' &&
        path[8] == 'b' && path[9] == '/' && path[10] == 'm' && path[11] == 'a' &&
        path[12] == 'g' && path[13] == 'i' && path[14] == 's' && path[15] == 'k' &&
        path[16] == '/' && path[17] == 's' && path[18] == 'u' && path[19] == '\0')
        return 1;
    
    // /debug_ramdisk/su
    if (path[0] == '/' && path[1] == 'd' && path[2] == 'e' && path[3] == 'b' &&
        path[4] == 'u' && path[5] == 'g' && path[6] == '_' && path[7] == 'r' &&
        path[8] == 'a' && path[9] == 'm' && path[10] == 'd' && path[11] == 'i' &&
        path[12] == 's' && path[13] == 'k' && path[14] == '/' && path[15] == 's' &&
        path[16] == 'u' && path[17] == '\0')
        return 1;
    
    // /usr/bin/su
    if (path[0] == '/' && path[1] == 'u' && path[2] == 's' && path[3] == 'r' &&
        path[4] == '/' && path[5] == 'b' && path[6] == 'i' && path[7] == 'n' &&
        path[8] == '/' && path[9] == 's' && path[10] == 'u' && path[11] == '\0')
        return 1;
    
    // Full path matching for common sudo locations
    // /usr/bin/sudo
    if (path[0] == '/' && path[1] == 'u' && path[2] == 's' && path[3] == 'r' &&
        path[4] == '/' && path[5] == 'b' && path[6] == 'i' && path[7] == 'n' &&
        path[8] == '/' && path[9] == 's' && path[10] == 'u' && path[11] == 'd' &&
        path[12] == 'o' && path[13] == '\0')
        return 2;
    
    // /bin/sudo
    if (path[0] == '/' && path[1] == 'b' && path[2] == 'i' && path[3] == 'n' &&
        path[4] == '/' && path[5] == 's' && path[6] == 'u' && path[7] == 'd' &&
        path[8] == 'o' && path[9] == '\0')
        return 2;
    
    // /system/bin/sudo
    if (path[0] == '/' && path[1] == 's' && path[2] == 'y' && path[3] == 's' &&
        path[4] == 't' && path[5] == 'e' && path[6] == 'm' && path[7] == '/' &&
        path[8] == 'b' && path[9] == 'i' && path[10] == 'n' && path[11] == '/' &&
        path[12] == 's' && path[13] == 'u' && path[14] == 'd' && path[15] == 'o' &&
        path[16] == '\0')
        return 2;
    
    // /system/xbin/sudo
    if (path[0] == '/' && path[1] == 's' && path[2] == 'y' && path[3] == 's' &&
        path[4] == 't' && path[5] == 'e' && path[6] == 'm' && path[7] == '/' &&
        path[8] == 'x' && path[9] == 'b' && path[10] == 'i' && path[11] == 'n' &&
        path[12] == '/' && path[13] == 's' && path[14] == 'u' && path[15] == 'd' &&
        path[16] == 'o' && path[17] == '\0')
        return 2;
    
    return 0;
}

// Result codes for su/sudo alert
#define SU_SUDO_RESULT_ATTEMPTED    0  // Attempt detected at syscall entry (outcome unknown)
#define SU_SUDO_RESULT_SUCCESSFUL   1  // Execution succeeded (retval == 0 at exit)
#define SU_SUDO_RESULT_DENIED       2  // Permission denied (EACCES/-13 or EPERM/-1)
#define SU_SUDO_RESULT_NOT_FOUND    3  // File not found (ENOENT/-2)
#define SU_SUDO_RESULT_FAILED       4  // Other failure

// Access type constants for SELinux protected resource access alert
#define ACCESS_TYPE_READ    1
#define ACCESS_TYPE_WRITE   2
#define ACCESS_TYPE_EXECUTE 3
#define ACCESS_TYPE_STAT    4
#define ACCESS_TYPE_UNKNOWN 5

// Result constants for SELinux protected resource access alert
#define ACCESS_RESULT_DENIED  0
#define ACCESS_RESULT_ALLOWED 1

// Sensitive path type constants (returned by get_sensitive_path_type)
#define SENSITIVE_PATH_NONE            0
#define SENSITIVE_PATH_DATA_SYSTEM     1
#define SENSITIVE_PATH_DATA_KEYSTORE   2
#define SENSITIVE_PATH_DEV             3
#define SENSITIVE_PATH_SYSTEM_BIN      4

// Check if the path matches one of the sensitive prefixes
// Returns: 1=/data/system/, 2=/data/misc/keystore, 3=/dev/, 4=/system/bin/, 0=no match
static __always_inline int get_sensitive_path_type(char *path_p, char *matched_prefix_out)
{
    char path[64];
    bpf_probe_read_str(path, sizeof(path), path_p);
    
    // Initialize matched_prefix to empty
    matched_prefix_out[0] = '\0';
    
    // Check for /data/system/ (13 chars including trailing slash)
    // "/data/system/"
    if (path[0] == '/' && path[1] == 'd' && path[2] == 'a' && path[3] == 't' &&
        path[4] == 'a' && path[5] == '/' && path[6] == 's' && path[7] == 'y' &&
        path[8] == 's' && path[9] == 't' && path[10] == 'e' && path[11] == 'm' &&
        path[12] == '/') {
        // Copy prefix "/data/system/"
        matched_prefix_out[0] = '/'; matched_prefix_out[1] = 'd'; matched_prefix_out[2] = 'a';
        matched_prefix_out[3] = 't'; matched_prefix_out[4] = 'a'; matched_prefix_out[5] = '/';
        matched_prefix_out[6] = 's'; matched_prefix_out[7] = 'y'; matched_prefix_out[8] = 's';
        matched_prefix_out[9] = 't'; matched_prefix_out[10] = 'e'; matched_prefix_out[11] = 'm';
        matched_prefix_out[12] = '/'; matched_prefix_out[13] = '\0';
        return SENSITIVE_PATH_DATA_SYSTEM;
    }
    
    // Check for /data/misc/keystore (20 chars) - matches exactly or as prefix
    // "/data/misc/keystore"
    if (path[0] == '/' && path[1] == 'd' && path[2] == 'a' && path[3] == 't' &&
        path[4] == 'a' && path[5] == '/' && path[6] == 'm' && path[7] == 'i' &&
        path[8] == 's' && path[9] == 'c' && path[10] == '/' && path[11] == 'k' &&
        path[12] == 'e' && path[13] == 'y' && path[14] == 's' && path[15] == 't' &&
        path[16] == 'o' && path[17] == 'r' && path[18] == 'e' && 
        (path[19] == '\0' || path[19] == '/')) {
        // Copy prefix "/data/misc/keystore"
        matched_prefix_out[0] = '/'; matched_prefix_out[1] = 'd'; matched_prefix_out[2] = 'a';
        matched_prefix_out[3] = 't'; matched_prefix_out[4] = 'a'; matched_prefix_out[5] = '/';
        matched_prefix_out[6] = 'm'; matched_prefix_out[7] = 'i'; matched_prefix_out[8] = 's';
        matched_prefix_out[9] = 'c'; matched_prefix_out[10] = '/'; matched_prefix_out[11] = 'k';
        matched_prefix_out[12] = 'e'; matched_prefix_out[13] = 'y'; matched_prefix_out[14] = 's';
        matched_prefix_out[15] = 't'; matched_prefix_out[16] = 'o'; matched_prefix_out[17] = 'r';
        matched_prefix_out[18] = 'e'; matched_prefix_out[19] = '\0';
        return SENSITIVE_PATH_DATA_KEYSTORE;
    }
    
    // Check for sensitive /dev/ paths (not all /dev/ - that's too noisy)
    // Only match truly sensitive devices, exclude common harmless ones:
    // - /dev/null, /dev/zero, /dev/urandom, /dev/random (utility devices)
    // - /dev/tty, /dev/pts/*, /dev/ptmx (terminal devices)
    // - /dev/__properties__/* (Android property system)
    if (path[0] == '/' && path[1] == 'd' && path[2] == 'e' && path[3] == 'v' &&
        path[4] == '/') {
        
        // Skip /dev/null
        if (path[5] == 'n' && path[6] == 'u' && path[7] == 'l' && path[8] == 'l' && path[9] == '\0') {
            return SENSITIVE_PATH_NONE;
        }
        // Skip /dev/zero
        if (path[5] == 'z' && path[6] == 'e' && path[7] == 'r' && path[8] == 'o' && path[9] == '\0') {
            return SENSITIVE_PATH_NONE;
        }
        // Skip /dev/urandom
        if (path[5] == 'u' && path[6] == 'r' && path[7] == 'a' && path[8] == 'n' &&
            path[9] == 'd' && path[10] == 'o' && path[11] == 'm' && path[12] == '\0') {
            return SENSITIVE_PATH_NONE;
        }
        // Skip /dev/random
        if (path[5] == 'r' && path[6] == 'a' && path[7] == 'n' && path[8] == 'd' &&
            path[9] == 'o' && path[10] == 'm' && path[11] == '\0') {
            return SENSITIVE_PATH_NONE;
        }
        // Skip /dev/tty (terminal)
        if (path[5] == 't' && path[6] == 't' && path[7] == 'y' && (path[8] == '\0' || path[8] == '/')) {
            return SENSITIVE_PATH_NONE;
        }
        // Skip /dev/pts/ (pseudo-terminals)
        if (path[5] == 'p' && path[6] == 't' && path[7] == 's' && path[8] == '/') {
            return SENSITIVE_PATH_NONE;
        }
        // Skip /dev/ptmx (pseudo-terminal master)
        if (path[5] == 'p' && path[6] == 't' && path[7] == 'm' && path[8] == 'x' && path[9] == '\0') {
            return SENSITIVE_PATH_NONE;
        }
        // Skip /dev/__properties__/ (Android property system - normal behavior)
        if (path[5] == '_' && path[6] == '_' && path[7] == 'p' && path[8] == 'r' &&
            path[9] == 'o' && path[10] == 'p' && path[11] == 'e' && path[12] == 'r' &&
            path[13] == 't' && path[14] == 'i' && path[15] == 'e' && path[16] == 's' &&
            path[17] == '_' && path[18] == '_' && path[19] == '/') {
            return SENSITIVE_PATH_NONE;
        }
        // Skip /dev/ashmem (shared memory - very common)
        if (path[5] == 'a' && path[6] == 's' && path[7] == 'h' && path[8] == 'm' &&
            path[9] == 'e' && path[10] == 'm') {
            return SENSITIVE_PATH_NONE;
        }
        // Skip /dev/binder (Android binder - very common IPC)
        if (path[5] == 'b' && path[6] == 'i' && path[7] == 'n' && path[8] == 'd' &&
            path[9] == 'e' && path[10] == 'r') {
            return SENSITIVE_PATH_NONE;
        }
        // Skip /dev/hwbinder (Android hardware binder)
        if (path[5] == 'h' && path[6] == 'w' && path[7] == 'b' && path[8] == 'i' &&
            path[9] == 'n' && path[10] == 'd' && path[11] == 'e' && path[12] == 'r') {
            return SENSITIVE_PATH_NONE;
        }
        
        // If not excluded, this is a potentially sensitive /dev/ path
        // Copy prefix "/dev/"
        matched_prefix_out[0] = '/'; matched_prefix_out[1] = 'd'; matched_prefix_out[2] = 'e';
        matched_prefix_out[3] = 'v'; matched_prefix_out[4] = '/'; matched_prefix_out[5] = '\0';
        return SENSITIVE_PATH_DEV;
    }
    
    // Check for /system/bin/ (12 chars including trailing slash)
    // "/system/bin/"
    if (path[0] == '/' && path[1] == 's' && path[2] == 'y' && path[3] == 's' &&
        path[4] == 't' && path[5] == 'e' && path[6] == 'm' && path[7] == '/' &&
        path[8] == 'b' && path[9] == 'i' && path[10] == 'n' && path[11] == '/') {
        // Copy prefix "/system/bin/"
        matched_prefix_out[0] = '/'; matched_prefix_out[1] = 's'; matched_prefix_out[2] = 'y';
        matched_prefix_out[3] = 's'; matched_prefix_out[4] = 't'; matched_prefix_out[5] = 'e';
        matched_prefix_out[6] = 'm'; matched_prefix_out[7] = '/'; matched_prefix_out[8] = 'b';
        matched_prefix_out[9] = 'i'; matched_prefix_out[10] = 'n'; matched_prefix_out[11] = '/';
        matched_prefix_out[12] = '\0';
        return SENSITIVE_PATH_SYSTEM_BIN;
    }
    
    return SENSITIVE_PATH_NONE;
}

// Get syscall name string based on syscall ID
static __always_inline void get_syscall_name(int syscall_id, char *name_out)
{
    name_out[0] = '\0';
    
    if (syscall_id == SYS_OPEN) {
        name_out[0] = 'o'; name_out[1] = 'p'; name_out[2] = 'e'; name_out[3] = 'n';
        name_out[4] = '\0';
    } else if (syscall_id == SYS_OPENAT) {
        name_out[0] = 'o'; name_out[1] = 'p'; name_out[2] = 'e'; name_out[3] = 'n';
        name_out[4] = 'a'; name_out[5] = 't'; name_out[6] = '\0';
    }
    // For ARM64, we need to check the architecture-specific syscall numbers
    #if defined(bpf_target_arm64)
    else if (syscall_id == 21) { // access on ARM64 is 21
        name_out[0] = 'a'; name_out[1] = 'c'; name_out[2] = 'c'; name_out[3] = 'e';
        name_out[4] = 's'; name_out[5] = 's'; name_out[6] = '\0';
    } else if (syscall_id == 48) { // faccessat on ARM64 is 48
        name_out[0] = 'f'; name_out[1] = 'a'; name_out[2] = 'c'; name_out[3] = 'c';
        name_out[4] = 'e'; name_out[5] = 's'; name_out[6] = 's'; name_out[7] = 'a';
        name_out[8] = 't'; name_out[9] = '\0';
    }
    #else
    else if (syscall_id == 21) { // access on x86_64 is 21
        name_out[0] = 'a'; name_out[1] = 'c'; name_out[2] = 'c'; name_out[3] = 'e';
        name_out[4] = 's'; name_out[5] = 's'; name_out[6] = '\0';
    } else if (syscall_id == 269) { // faccessat on x86_64 is 269
        name_out[0] = 'f'; name_out[1] = 'a'; name_out[2] = 'c'; name_out[3] = 'c';
        name_out[4] = 'e'; name_out[5] = 's'; name_out[6] = 's'; name_out[7] = 'a';
        name_out[8] = 't'; name_out[9] = '\0';
    }
    #endif
    else {
        name_out[0] = 'u'; name_out[1] = 'n'; name_out[2] = 'k'; name_out[3] = 'n';
        name_out[4] = 'o'; name_out[5] = 'w'; name_out[6] = 'n'; name_out[7] = '\0';
    }
}

static __always_inline int init_context(context_t *context)
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    u64 id = bpf_get_current_pid_tgid();
    context->host_tid = id;
    context->host_pid = id >> 32;
    context->host_ppid = get_task_ppid(task);
    context->tid = get_task_ns_pid(task);
    context->pid = get_task_ns_tgid(task);
    context->ppid = get_task_ns_ppid(task);
    context->mnt_id = get_task_mnt_ns_id(task);
    context->pid_id = get_task_pid_ns_id(task);
    context->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&context->comm, sizeof(context->comm));
    char * uts_name = get_task_uts_name(task);
    if (uts_name)
        bpf_probe_read_str(&context->uts_name, TASK_COMM_LEN, uts_name);

    // Save timestamp in microsecond resolution
    context->ts = bpf_ktime_get_ns()/1000;

    // Clean Stack Trace ID
    context->stack_id = 0;

    return 0;
}

static __always_inline int get_config(u32 key)
{
    u32 *config = bpf_map_lookup_elem(&config_map, &key);

    if (config == NULL)
        return 0;

    return *config;
}

// returns 1 if you should trace based on uid, 0 if not
static __always_inline int uint_filter_matches(int filter_config, void *filter_map, u64 key, u32 less_idx, u32 greater_idx)
{
    int config = get_config(filter_config);
    if (!config)
        return 1;

    u8* equality = bpf_map_lookup_elem(filter_map, &key);
    if (equality != NULL) {
        return *equality;
    }

    if (config == FILTER_IN)
        return 0;

    u64* lessThan = bpf_map_lookup_elem(&inequality_filter, &less_idx);
    if (lessThan == NULL)
        return 1;

    if ((*lessThan != LESS_NOT_SET) && (key >= *lessThan)) {
        return 0;
    }

    u64* greaterThan = bpf_map_lookup_elem(&inequality_filter, &greater_idx);
    if (greaterThan == NULL)
        return 1;

    if ((*greaterThan != GREATER_NOT_SET) && (key <= *greaterThan)) {
        return 0;
    }

    return 1;
}

static __always_inline int equality_filter_matches(int filter_config, void *filter_map, void *key)
{
    int config = get_config(filter_config);
    if (!config)
        return 1;

    u32* equality = bpf_map_lookup_elem(filter_map, key);
    if (equality != NULL) {
        return *equality;
    }

    if (config == FILTER_IN)
        return 0;

    return 1;
}

static __always_inline int bool_filter_matches(int filter_config, bool val)
{
    int config = get_config(filter_config);
    if (!config)
        return 1;

    if ((config == FILTER_IN) && val){
        return 1;
    }

    if ((config == FILTER_OUT) && !val) {
        return 1;
    }

    return 0;
}

static __always_inline int should_trace()
{
    context_t context = {};
    init_context(&context);

    if (get_config(CONFIG_FOLLOW_FILTER)) {
        if (bpf_map_lookup_elem(&traced_pids_map, &context.host_tid) != 0)
            // If the process is already in the traced_pids_map and follow was chosen, don't check the other filters
            return 1;
    }

    bool is_new_pid = bpf_map_lookup_elem(&new_pids_map, &context.host_tid) != 0;
    if (!bool_filter_matches(CONFIG_NEW_PID_FILTER, is_new_pid))
    {
        return 0;
    }

    bool is_new_container = bpf_map_lookup_elem(&new_pidns_map, &context.pid_id) != 0;
    if (!bool_filter_matches(CONFIG_NEW_CONT_FILTER, is_new_container))
    {
        return 0;
    }

    // Don't monitor self
    if (get_config(CONFIG_TRACEE_PID) == context.host_pid) {
        return 0;
    }

    if (!uint_filter_matches(CONFIG_UID_FILTER, &uid_filter, context.uid, UID_LESS, UID_GREATER))
    {
        return 0; 
    }

    if (!uint_filter_matches(CONFIG_MNT_NS_FILTER, &mnt_ns_filter, context.mnt_id, MNTNS_LESS, MNTNS_GREATER))
    {
        return 0;
    }

    if (!uint_filter_matches(CONFIG_PID_NS_FILTER, &pid_ns_filter, context.pid_id, PIDNS_LESS, PIDNS_GREATER))
    {
        return 0;
    }

    if (!uint_filter_matches(CONFIG_PID_FILTER, &pid_filter, context.host_tid, PID_LESS, PID_GREATER))
    {
        return 0;
    }

    if (!equality_filter_matches(CONFIG_UTS_NS_FILTER, &uts_ns_filter, &context.uts_name))
    {
        return 0;
    }

    if (!equality_filter_matches(CONFIG_COMM_FILTER, &comm_filter, &context.comm))
    {
        return 0;
    }
    // TODO: after we move to minimal kernel 4.18, we can check for container by cgroupid != host cgroupid
    bool is_container = context.tid != context.host_tid;
    if (!bool_filter_matches(CONFIG_CONT_FILTER, is_container))
    {
        return 0;
    }

    // We passed all filters successfully
    return 1;
}

static __always_inline int event_chosen(u32 key)
{
    u32 *config = bpf_map_lookup_elem(&chosen_events_map, &key);
    if (config == NULL)
        return 0;

    return *config;
}

static __always_inline buf_t* get_buf(int idx)
{
    return bpf_map_lookup_elem(&bufs, &idx);
}

static __always_inline void set_buf_off(int buf_idx, u32 new_off)
{
    bpf_map_update_elem(&bufs_off, &buf_idx, &new_off, BPF_ANY);
}

static __always_inline u32* get_buf_off(int buf_idx)
{
    return bpf_map_lookup_elem(&bufs_off, &buf_idx);
}

// Context will always be at the start of the submission buffer
// It may be needed to resave the context if the arguments number changed by logic
static __always_inline int save_context_to_buf(buf_t *submit_p, void *ptr)
{
    int rc = bpf_probe_read(&(submit_p->buf[0]), sizeof(context_t), ptr);
    if (rc == 0)
        return sizeof(context_t);

    return 0;
}

static __always_inline context_t init_and_save_context(void* ctx, buf_t *submit_p, u32 id, u8 argnum, long ret)
{
    context_t context = {};
    init_context(&context);
    context.eventid = id;
    context.argnum = argnum;
    context.retval = ret;

    // Get Stack trace
    if (get_config(CONFIG_CAPTURE_STACK_TRACES)) {
        int stack_id = bpf_get_stackid(ctx, &stack_addresses, BPF_F_USER_STACK);
        if (stack_id >= 0) {
            context.stack_id = stack_id;
        }
    }

    save_context_to_buf(submit_p, (void*)&context);
    return context;
}

static __always_inline int save_to_submit_buf(buf_t *submit_p, void *ptr, u32 size, u8 type, u8 tag)
{
// The biggest element that can be saved with this function should be defined here
#define MAX_ELEMENT_SIZE sizeof(struct sockaddr_un)
    if (type == 0)
        return 0;

    if (size == 0)
        return 0;

    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return 0;
    if (*off > MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE)
        // Satisfy validator for probe read
        return 0;

    // Save argument type
    int rc = bpf_probe_read(&(submit_p->buf[*off]), 1, &type);
    if (rc != 0)
        return 0;

    *off += 1;

    if (*off > MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE)
        // Satisfy validator for probe read
        return 0;

    // Save argument tag
    rc = bpf_probe_read(&(submit_p->buf[*off]), 1, &tag);
    if (rc != 0) {
        *off -= 1;
        return 0;
    }
    *off += 1;

    if (*off > MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE) {
        // Satisfy validator for probe read
        *off -= 2;
        return 0;
    }

    // Read into buffer
    rc = bpf_probe_read(&(submit_p->buf[*off]), size, ptr);
    if (rc == 0) {
        *off += size;
        return 1;
    }

    *off -= 2;
    return 0;
}

static __always_inline int save_str_to_buf(buf_t *submit_p, void *ptr, u8 tag)
{
    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return 0;
    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
        // not enough space - return
        return 0;

    // Save argument type
    u8 type = STR_T;
    bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE-1)]), 1, &type);

    *off += 1;

    // Save argument tag
    if (tag != TAG_NONE) {
        int rc = bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE-1)]), 1, &tag);
        if (rc != 0) {
            *off -= 1;
            return 0;
        }

        *off += 1;
    }

    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int)) {
        // Satisfy validator for probe read
        *off -= 2;
        return 0;
    }

    // Read into buffer
    int sz = bpf_probe_read_str(&(submit_p->buf[*off + sizeof(int)]), MAX_STRING_SIZE, ptr);
    if (sz > 0) {
        if (*off > MAX_PERCPU_BUFSIZE - sizeof(int)) {
            // Satisfy validator for probe read
            *off -= 2;
            return 0;
        }
        bpf_probe_read(&(submit_p->buf[*off]), sizeof(int), &sz);
        *off += sz + sizeof(int);
        return 1;
    }

    *off -= 2;
    return 0;
}

static __always_inline int save_str_arr_to_buf(buf_t *submit_p, const char __user *const __user *ptr, u8 tag)
{
    u8 elem_num = 0;

    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return 0;

    // mark string array start
    u8 type = STR_ARR_T;
    int rc = bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE-1)]), 1, &type);
    if (rc != 0)
        return 0;

    *off += 1;

    // Save argument tag
    rc = bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE-1)]), 1, &tag);
    if (rc != 0) {
        *off -= 1;
        return 0;
    }

    *off += 1;

    // Save space for number of elements
    u32 orig_off = *off;
    *off += 1;

    #pragma unroll
    for (int i = 0; i < MAX_STR_ARR_ELEM; i++) {
        const char *argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), &ptr[i]);
        if (!argp)
            goto out;

        if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
            // not enough space - return
            goto out;

        // Read into buffer
        int sz = bpf_probe_read_str(&(submit_p->buf[*off + sizeof(int)]), MAX_STRING_SIZE, argp);
        if (sz > 0) {
            if (*off > MAX_PERCPU_BUFSIZE - sizeof(int))
                // Satisfy validator for probe read
                goto out;
            bpf_probe_read(&(submit_p->buf[*off]), sizeof(int), &sz);
            *off += sz + sizeof(int);
            elem_num++;
            continue;
        } else {
            goto out;
        }
    }
    // handle truncated argument list
    char ellipsis[] = "...";
    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
        // not enough space - return
        goto out;

    // Read into buffer
    int sz = bpf_probe_read_str(&(submit_p->buf[*off + sizeof(int)]), MAX_STRING_SIZE, ellipsis);
    if (sz > 0) {
        if (*off > MAX_PERCPU_BUFSIZE - sizeof(int))
            // Satisfy validator for probe read
            goto out;
        bpf_probe_read(&(submit_p->buf[*off]), sizeof(int), &sz);
        *off += sz + sizeof(int);
        elem_num++;
    }
out:
    // save number of elements in the array
    bpf_probe_read(&(submit_p->buf[orig_off & (MAX_PERCPU_BUFSIZE-1)]), 1, &elem_num);
    return 1;
}

static __always_inline int save_file_path_to_str_buf(buf_t *string_p, struct file* file)
{
    struct path f_path = get_path_from_file(file);
    char slash = '/';
    int zero = 0;
    struct dentry *dentry = f_path.dentry;
    struct vfsmount *vfsmnt = f_path.mnt;
    struct mount *mnt_p = real_mount(vfsmnt);
    struct mount mnt;
    bpf_probe_read(&mnt, sizeof(struct mount), mnt_p);

    u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1);

    #pragma unroll
    // As bpf loops are not allowed and max instructions number is 4096, path components is limited to 30
    for (int i = 0; i < 30; i++) {
        struct dentry *mnt_root = get_mnt_root_ptr_from_vfsmnt(vfsmnt);
        struct dentry *d_parent = get_d_parent_ptr_from_dentry(dentry);
        if (dentry == mnt_root || dentry == d_parent) {
            if (dentry != mnt_root) {
                // We reached root, but not mount root - escaped?
                break;
            }
            if (mnt_p != mnt.mnt_parent) {
                // We reached root, but not global root - continue with mount point path
                dentry = mnt.mnt_mountpoint;
                bpf_probe_read(&mnt, sizeof(struct mount), mnt.mnt_parent);
                vfsmnt = &mnt.mnt;
                continue;
            }
            // Global root - path fully parsed
            break;
        }
        // Add this dentry name to path
        struct qstr d_name = get_d_name_from_dentry(dentry);
        unsigned int len = (d_name.len+1) & (MAX_STRING_SIZE-1);
        unsigned int off = buf_off - len;
        // Is string buffer big enough for dentry name?
        int sz = 0;
        if (off <= buf_off) { // verify no wrap occured
            len = ((len - 1) & ((MAX_PERCPU_BUFSIZE >> 1)-1)) + 1;
            sz = bpf_probe_read_str(&(string_p->buf[off & ((MAX_PERCPU_BUFSIZE >> 1)-1)]), len, (void *)d_name.name);
        }
        else
            break;
        if (sz > 1) {
            buf_off -= 1; // remove null byte termination with slash sign
            bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE-1)]), 1, &slash);
            buf_off -= sz - 1;
        } else {
            // If sz is 0 or 1 we have an error (path can't be null nor an empty string)
            break;
        }
        dentry = d_parent;
    }

    if (buf_off == (MAX_PERCPU_BUFSIZE >> 1)) {
        // memfd files have no path in the filesystem -> extract their name
        buf_off = 0;
        struct qstr d_name = get_d_name_from_dentry(dentry);
        bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void *)d_name.name);
    } else {
        // Add leading slash
        buf_off -= 1;
        bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE-1)]), 1, &slash);
        // Null terminate the path string
        bpf_probe_read(&(string_p->buf[(MAX_PERCPU_BUFSIZE >> 1)-1]), 1, &zero);
    }

    set_buf_off(STRING_BUF_IDX, buf_off);
    return buf_off;
}

static __always_inline int save_dentry_path_to_str_buf(buf_t *string_p, struct dentry* dentry)
{
    char slash = '/';
    int zero = 0;

    u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1);

    #pragma unroll
    // As bpf loops are not allowed and max instructions number is 4096, path components is limited to 30
    for (int i = 0; i < 30; i++) {
        struct dentry *d_parent = get_d_parent_ptr_from_dentry(dentry);
        if (dentry == d_parent) {
            break;
        }
        // Add this dentry name to path
        struct qstr d_name = get_d_name_from_dentry(dentry);
        unsigned int len = (d_name.len+1) & (MAX_STRING_SIZE-1);
        unsigned int off = buf_off - len;
        // Is string buffer big enough for dentry name?
        int sz = 0;
        if (off <= buf_off) { // verify no wrap occured
            len = ((len - 1) & ((MAX_PERCPU_BUFSIZE >> 1)-1)) + 1;
            sz = bpf_probe_read_str(&(string_p->buf[off & ((MAX_PERCPU_BUFSIZE >> 1)-1)]), len, (void *)d_name.name);
        }
        else
            break;
        if (sz > 1) {
            buf_off -= 1; // remove null byte termination with slash sign
            bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE-1)]), 1, &slash);
            buf_off -= sz - 1;
        } else {
            // If sz is 0 or 1 we have an error (path can't be null nor an empty string)
            break;
        }
        dentry = d_parent;
    }

    if (buf_off == (MAX_PERCPU_BUFSIZE >> 1)) {
        // memfd files have no path in the filesystem -> extract their name
        buf_off = 0;
        struct qstr d_name = get_d_name_from_dentry(dentry);
        bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void *)d_name.name);
    } else {
        // Add leading slash
        buf_off -= 1;
        bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE-1)]), 1, &slash);
        // Null terminate the path string
        bpf_probe_read(&(string_p->buf[(MAX_PERCPU_BUFSIZE >> 1)-1]), 1, &zero);
    }

    set_buf_off(STRING_BUF_IDX, buf_off);
    return buf_off;
}

static __always_inline int events_perf_submit(void *ctx)
{
    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return -1;
    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return -1;

    /* satisfy validator by setting buffer bounds */
    int size = ((*off - 1) & (MAX_PERCPU_BUFSIZE-1)) + 1;
    void * data = submit_p->buf;
    return bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, size);
}

static __always_inline int save_args(args_t *args, u32 event_id)
{
    u64 id = event_id;
    u32 tid = bpf_get_current_pid_tgid();
    id = id << 32 | tid;
    bpf_map_update_elem(&args_map, &id, args, BPF_ANY);

    return 0;
}

static __always_inline int save_args_from_regs(struct pt_regs *ctx, u32 event_id, bool is_syscall)
{
    args_t args = {};

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (is_x86_compat(task) && is_syscall) {
#if defined(bpf_target_x86)
        args.args[0] = ctx->bx;
        args.args[1] = ctx->cx;
        args.args[2] = ctx->dx;
        args.args[3] = ctx->si;
        args.args[4] = ctx->di;
        args.args[5] = ctx->bp;
#endif
    } else {
        args.args[0] = PT_REGS_PARM1(ctx);
        args.args[1] = PT_REGS_PARM2(ctx);
        args.args[2] = PT_REGS_PARM3(ctx);
        args.args[3] = PT_REGS_PARM4(ctx);
        args.args[4] = PT_REGS_PARM5(ctx);
        args.args[5] = PT_REGS_PARM6(ctx);
    }

    return save_args(&args, event_id);
}

static __always_inline int load_args(args_t *args, bool delete, u32 event_id)
{
    args_t *saved_args;
    u32 tid = bpf_get_current_pid_tgid();
    u64 id = event_id;
    id = id << 32 | tid;

    saved_args = bpf_map_lookup_elem(&args_map, &id);
    if (saved_args == 0) {
        // missed entry or not a container
        return -1;
    }

    args->args[0] = saved_args->args[0];
    args->args[1] = saved_args->args[1];
    args->args[2] = saved_args->args[2];
    args->args[3] = saved_args->args[3];
    args->args[4] = saved_args->args[4];
    args->args[5] = saved_args->args[5];

    if (delete)
        bpf_map_delete_elem(&args_map, &id);

    return 0;
}

static __always_inline int del_args(u32 event_id)
{
    u32 tid = bpf_get_current_pid_tgid();
    u64 id = event_id;
    id = id << 32 | tid;

    bpf_map_delete_elem(&args_map, &id);

    return 0;
}

static __always_inline int save_retval(u64 retval, u32 event_id)
{
    u64 id = event_id;
    u32 tid = bpf_get_current_pid_tgid();
    id = id << 32 | tid;

    bpf_map_update_elem(&ret_map, &id, &retval, BPF_ANY);

    return 0;
}

static __always_inline int load_retval(u64 *retval, u32 event_id)
{
    u64 id = event_id;
    u32 tid = bpf_get_current_pid_tgid();
    id = id << 32 | tid;

    u64 *saved_retval = bpf_map_lookup_elem(&ret_map, &id);
    if (saved_retval == 0) {
        // missed entry or not traced
        return -1;
    }

    *retval = *saved_retval;
    bpf_map_delete_elem(&ret_map, &id);

    return 0;
}

static __always_inline int del_retval(u32 event_id)
{
    u64 id = event_id;
    u32 tid = bpf_get_current_pid_tgid();
    id = id << 32 | tid;

    bpf_map_delete_elem(&ret_map, &id);

    return 0;
}

#define DEC_ARG(n, enc_arg) ((enc_arg>>(8*n))&0xFF)

static __always_inline int save_args_to_submit_buf(u64 types, u64 tags, args_t *args)
{
    unsigned int i;
    unsigned int rc = 0;
    unsigned int arg_num = 0;
    short family = 0;

    if (types == 0)
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    #pragma unroll
    for(i=0; i<6; i++)
    {
        int size = 0;
        u8 type = DEC_ARG(i, types);
        u8 tag = DEC_ARG(i, tags);
        switch (type)
        {
            case NONE_T:
                break;
            case INT_T:
                size = sizeof(int);
                break;
            case UINT_T:
                size = sizeof(unsigned int);
                break;
            case OFF_T_T:
                size = sizeof(off_t);
                break;
            case DEV_T_T:
                size = sizeof(dev_t);
                break;
            case MODE_T_T:
                size = sizeof(mode_t);
                break;
            case LONG_T:
                size = sizeof(long);
                break;
            case ULONG_T:
                size = sizeof(unsigned long);
                break;
            case SIZE_T_T:
                size = sizeof(size_t);
                break;
            case POINTER_T:
                size = sizeof(void*);
                break;
            case STR_T:
                rc = save_str_to_buf(submit_p, (void *)args->args[i], tag);
                break;
            case SOCKADDR_T:
                if (args->args[i]) {
                    bpf_probe_read(&family, sizeof(short), (void*)args->args[i]);
                    switch (family)
                    {
                        case AF_UNIX:
                            size = sizeof(struct sockaddr_un);
                            break;
                        case AF_INET:
                            size = sizeof(struct sockaddr_in);
                            break;
                        case AF_INET6:
                            size = sizeof(struct sockaddr_in6);
                            break;
                        default:
                            size = sizeof(short);
                    }
                    rc = save_to_submit_buf(submit_p, (void*)(args->args[i]), size, type, tag);
                } else {
                    rc = save_to_submit_buf(submit_p, &family, sizeof(short), type, tag);
                }
                break;
        }
        if ((type != NONE_T) && (type != STR_T) && (type != SOCKADDR_T))
            rc = save_to_submit_buf(submit_p, (void*)&(args->args[i]), size, type, tag);

        if (rc > 0) {
            arg_num++;
            rc = 0;
        }
    }

    return arg_num;
}

static __always_inline int trace_ret_generic(void *ctx, u32 id, u64 types, u64 tags, args_t *args, long ret)
{
    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    u8 argnum = save_args_to_submit_buf(types, tags, args);
    init_and_save_context(ctx, submit_p, id, argnum, ret);

    events_perf_submit(ctx);
    return 0;
}

#define TRACE_ENT_FUNC(name, id)                                        \
int trace_##name(void *ctx)                                             \
{                                                                       \
    if (!should_trace())                                                \
        return 0;                                                       \
    return save_args_from_regs(ctx, id, false);                         \
}

#define TRACE_RET_FUNC(name, id, types, tags, ret)                      \
int trace_ret_##name(void *ctx)                                         \
{                                                                       \
    args_t args = {};                                                   \
                                                                        \
    bool delete_args = true;                                            \
    if (load_args(&args, delete_args, id) != 0)                         \
        return -1;                                                      \
                                                                        \
    if (!should_trace())                                                \
        return -1;                                                      \
                                                                        \
    if (!event_chosen(id))                                              \
        return 0;                                                       \
                                                                        \
    return trace_ret_generic(ctx, id, types, tags, &args, ret);         \
}

/*============================== SYSCALL HOOKS ==============================*/

struct trace_event_raw_sys_enter {
  unsigned long long unused;
  long int id;
  long unsigned int args[6];
};

// include/trace/events/syscalls.h:
// TP_PROTO(struct pt_regs *regs, long id)
SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
struct trace_event_raw_sys_enter *args
#else
struct bpf_raw_tracepoint_args *ctx
#endif
)
{
    args_t args_tmp = {};
    int id;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
    void *ctx = args;
    id = args->id;

    args_tmp.args[0] = args->args[0];
    args_tmp.args[1] = args->args[1];
    args_tmp.args[2] = args->args[2];
    args_tmp.args[3] = args->args[3];
    args_tmp.args[4] = args->args[4];
    args_tmp.args[5] = args->args[5];
#else // LINUX_VERSION_CODE
    id = ctx->args[1];
#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
    struct pt_regs *regs = (struct pt_regs *) ctx->args[0];

    if (is_x86_compat(task)) {
#if defined(bpf_target_x86)
        args_tmp.args[0] = READ_KERN(regs->bx);
        args_tmp.args[1] = READ_KERN(regs->cx);
        args_tmp.args[2] = READ_KERN(regs->dx);
        args_tmp.args[3] = READ_KERN(regs->si);
        args_tmp.args[4] = READ_KERN(regs->di);
        args_tmp.args[5] = READ_KERN(regs->bp);
#endif // bpf_target_x86
    } else {
        args_tmp.args[0] = READ_KERN(PT_REGS_PARM1(regs));
        args_tmp.args[1] = READ_KERN(PT_REGS_PARM2(regs));
        args_tmp.args[2] = READ_KERN(PT_REGS_PARM3(regs));
#if defined(bpf_target_x86)
        // x86-64: r10 used instead of rcx (4th param to a syscall)
        args_tmp.args[3] = READ_KERN(regs->r10);
#else
        args_tmp.args[3] = READ_KERN(PT_REGS_PARM4(regs));
#endif
        args_tmp.args[4] = READ_KERN(PT_REGS_PARM5(regs));
        args_tmp.args[5] = READ_KERN(PT_REGS_PARM6(regs));
    }
#else // CONFIG_ARCH_HAS_SYSCALL_WRAPPER
    bpf_probe_read(args_tmp.args, sizeof(6 * sizeof(u64)), (void *) ctx->args);
#endif // CONFIG_ARCH_HAS_SYSCALL_WRAPPER
#endif // LINUX_VERSION_CODE

    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }

    u32 pid = bpf_get_current_pid_tgid();
    u32 uid = bpf_get_current_uid_gid();
    u32 *prev_uid = bpf_map_lookup_elem(&pid_to_uid, &pid);

    if (prev_uid == 0) {
        // If this is the first time we see this uid - save it
        bpf_map_update_elem(&pid_to_uid, &pid, &uid, BPF_ANY);
    } else if (*prev_uid != uid) {
        // A non root user change it's uid -> alert!
        buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
        if (submit_p == NULL)
            return 0;
        set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

        context_t context = init_and_save_context(ctx, submit_p, UID_CHANGE_ALERT, 2 /*argnum*/, 0 /*ret*/);

        u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
        if (!tags) {
            return -1;
        }

        save_to_submit_buf(submit_p, prev_uid, sizeof(unsigned int), UINT_T, DEC_ARG(0, *tags));
        save_to_submit_buf(submit_p, &uid, sizeof(unsigned int), UINT_T, DEC_ARG(1, *tags));

        events_perf_submit(ctx);

        bpf_map_update_elem(&pid_to_uid, &pid, &uid, BPF_ANY);
    }

    // execve events may add new pids to the traced pids set
    // perform this check before should_trace() so newly executed binaries will be traced
    if (id == SYS_EXECVE || id == SYS_EXECVEAT) {
        if (get_config(CONFIG_NEW_CONT_FILTER)) {
            u32 pid_ns = get_task_pid_ns_id(task);
            if (get_task_ns_pid(task) == 1) {
                // A new container/pod was started (pid 1 in namespace executed) - add pid namespace to map
                bpf_map_update_elem(&new_pidns_map, &pid_ns, &pid_ns, BPF_ANY);
            }
        }
        if (get_config(CONFIG_NEW_PID_FILTER)) {
            bpf_map_update_elem(&new_pids_map, &pid, &pid, BPF_ANY);
        }
        
        // SU/SUDO DETECTION AT SYSCALL ENTRY - catches attempts before SELinux denies them
        // This runs BEFORE should_trace() so we detect attempts from all processes including untrusted_app
        if (event_chosen(SU_SUDO_ALERT)) {
            // For execve: args[0] = filename (USER-SPACE pointer)
            // For execveat: args[1] = filename (args[0] = dirfd)
            char *filename_ptr = (id == SYS_EXECVE) ? 
                (char *)args_tmp.args[0] : (char *)args_tmp.args[1];
            
            if (filename_ptr != NULL) {
                // Read filename from USER SPACE into local buffer
                char filename_buf[64];
                __builtin_memset(filename_buf, 0, sizeof(filename_buf));
                
                // Try bpf_probe_read_user_str first (kernel 5.x+), then fallback to bpf_probe_read_str
                int len = bpf_probe_read_user_str(filename_buf, sizeof(filename_buf), filename_ptr);
                if (len <= 0) {
                    // Fallback for older kernels where bpf_probe_read_str works for user space
                    len = bpf_probe_read_str(filename_buf, sizeof(filename_buf), filename_ptr);
                }
                
                if (len > 0) {
                    // Check if it's su or sudo using the kernel-space buffer we just populated
                    int su_sudo_type = is_su_sudo_cmd(filename_buf);
                    if (su_sudo_type > 0) {
                        buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
                        if (submit_p != NULL) {
                            set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));
                            
                            // Use retval=0 as this is entry time, actual result unknown
                            context_t context = init_and_save_context(ctx, submit_p, SU_SUDO_ALERT, 3 /*argnum*/, 0 /*ret*/);
                            
                            u64 *su_sudo_tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
                            if (su_sudo_tags) {
                                // Arg 0: command_type (1=su, 2=sudo)
                                u32 cmd_type = (u32)su_sudo_type;
                                // Arg 1: pathname (use our kernel-space copy)
                                // Arg 2: result (0=attempted - outcome not yet known at entry)
                                u32 result = SU_SUDO_RESULT_ATTEMPTED;
                                
                                save_to_submit_buf(submit_p, &cmd_type, sizeof(u32), UINT_T, DEC_ARG(0, *su_sudo_tags));
                                save_str_to_buf(submit_p, (void *)filename_buf, DEC_ARG(1, *su_sudo_tags));
                                save_to_submit_buf(submit_p, &result, sizeof(u32), UINT_T, DEC_ARG(2, *su_sudo_tags));
                                events_perf_submit(ctx);
                            }
                        }
                    }
                }
            }
        }
    }

    if (!should_trace())
        return 0;

    if (id == SYS_EXECVE || id == SYS_EXECVEAT) {
        // We passed all filters (in should_trace()) - add this pid to traced pids set
        bpf_map_update_elem(&traced_pids_map, &pid, &pid, BPF_ANY);
    }

    if (event_chosen(RAW_SYS_ENTER)) {
        buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
        if (submit_p == NULL)
            return 0;
        set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

        context_t context = init_and_save_context(ctx, submit_p, RAW_SYS_ENTER, 1 /*argnum*/, 0 /*ret*/);

        u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
        if (!tags) {
            return -1;
        }

        save_to_submit_buf(submit_p, (void*)&id, sizeof(int), INT_T, DEC_ARG(0, *tags));
        events_perf_submit(ctx);
    }

    // exit, exit_group and rt_sigreturn syscalls don't return - don't save args for them
    if (id != SYS_EXIT && id != SYS_EXIT_GROUP && id != SYS_RT_SIGRETURN) {
        save_args(&args_tmp, id);
    }

    // call syscall handler, if exists
    // enter tail calls should never delete saved args
    bpf_tail_call(ctx, &sys_enter_tails, id);
    return 0;
}

struct trace_event_raw_sys_exit {
  unsigned long long unused;
  long int id;
  long int ret;
};

// include/trace/events/syscalls.h:
// TP_PROTO(struct pt_regs *regs, long ret)
SEC("raw_tracepoint/sys_exit")
int tracepoint__raw_syscalls__sys_exit(
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
struct trace_event_raw_sys_exit *args
#else
struct bpf_raw_tracepoint_args *ctx
#endif
)
{
    int id;
    long ret;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
    void *ctx = args;
    id = args->id;
    ret = args->ret;
#else
    struct pt_regs *regs = (struct pt_regs*)ctx->args[0];
    id = get_syscall_id_from_regs(regs);
    ret = ctx->args[1];
#endif

    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }

    args_t saved_args = {};
    bool delete_args = true;
    if (load_args(&saved_args, delete_args, id) != 0)
        return 0;

    if (!should_trace())
        return 0;

    // fork events may add new pids to the traced pids set
    // perform this check after should_trace() to only add forked childs of a traced parent
    if (id == SYS_CLONE || id == SYS_FORK || id == SYS_VFORK) {
        u32 pid = ret;
        bpf_map_update_elem(&traced_pids_map, &pid, &pid, BPF_ANY);
        if (get_config(CONFIG_NEW_PID_FILTER)) {
            bpf_map_update_elem(&new_pids_map, &pid, &pid, BPF_ANY);
        }
    }

    if (event_chosen(RAW_SYS_EXIT)) {
        buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
        if (submit_p == NULL)
            return 0;
        set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

        context_t context = init_and_save_context(ctx, submit_p, RAW_SYS_EXIT, 1 /*argnum*/, ret);

        u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
        if (!tags) {
            return -1;
        }

        save_to_submit_buf(submit_p, (void*)&id, sizeof(int), INT_T, DEC_ARG(0, *tags));
        events_perf_submit(ctx);
    }

    // SELinux mode change detection: catch failed openat attempts on /sys/fs/selinux/enforce
    // This triggers when permission is denied before vfs_write/security_file_open are called
    if (event_chosen(SELINUX_MODE_CHANGE_ALERT) && 
        (id == SYS_OPENAT || id == SYS_OPEN) && 
        ret < 0) {  // Failed open
        
        // Check if write flags were set
        // For openat: args[2] = flags; For open: args[1] = flags
        int flags;
        if (id == SYS_OPENAT) {
            flags = (int)saved_args.args[2];
        } else {
            flags = (int)saved_args.args[1];
        }
        
        // O_WRONLY=1, O_RDWR=2 - check if either bit is set
        if ((flags & 3) != 0) {
            // Read pathname from saved args
            // For openat: args[1] = pathname; For open: args[0] = pathname
            char path[32];
            const char *pathname;
            if (id == SYS_OPENAT) {
                pathname = (const char *)saved_args.args[1];
            } else {
                pathname = (const char *)saved_args.args[0];
            }
            
            bpf_probe_read_str(path, sizeof(path), pathname);
            
            // Check for "/sys/fs/selinux/enforce" (24 chars)
            if (path[0] == '/' && path[1] == 's' && path[2] == 'y' && path[3] == 's' &&
                path[4] == '/' && path[5] == 'f' && path[6] == 's' && path[7] == '/' &&
                path[8] == 's' && path[9] == 'e' && path[10] == 'l' && path[11] == 'i' &&
                path[12] == 'n' && path[13] == 'u' && path[14] == 'x' && path[15] == '/' &&
                path[16] == 'e' && path[17] == 'n' && path[18] == 'f' && path[19] == 'o' &&
                path[20] == 'r' && path[21] == 'c' && path[22] == 'e' && path[23] == '\0') {
                
                // Generate SELinux alert for denied open attempt
                buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
                if (submit_p != NULL) {
                    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));
                    context_t context = init_and_save_context(ctx, submit_p, SELINUX_MODE_CHANGE_ALERT, 4, ret);
                    
                    u64 *selinux_tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
                    if (selinux_tags) {
                        // Use SELINUX_OPEN_ATTEMPT to indicate open attempt was denied
                        u32 attempt_mode = SELINUX_OPEN_ATTEMPT;
                        u32 method = SELINUX_METHOD_WRITE;
                        char empty_str[1] = {0};
                        
                        save_to_submit_buf(submit_p, &attempt_mode, sizeof(u32), UINT_T, DEC_ARG(0, *selinux_tags));
                        save_to_submit_buf(submit_p, &method, sizeof(u32), UINT_T, DEC_ARG(1, *selinux_tags));
                        save_str_to_buf(submit_p, (void *)path, DEC_ARG(2, *selinux_tags));
                        save_str_to_buf(submit_p, (void *)empty_str, DEC_ARG(3, *selinux_tags));
                        events_perf_submit(ctx);
                    }
                }
            }
            
            // Check for "/sys/fs/selinux/load" (20 chars) - SELinux policy load file
            if (path[0] == '/' && path[1] == 's' && path[2] == 'y' && path[3] == 's' &&
                path[4] == '/' && path[5] == 'f' && path[6] == 's' && path[7] == '/' &&
                path[8] == 's' && path[9] == 'e' && path[10] == 'l' && path[11] == 'i' &&
                path[12] == 'n' && path[13] == 'u' && path[14] == 'x' && path[15] == '/' &&
                path[16] == 'l' && path[17] == 'o' && path[18] == 'a' && path[19] == 'd' &&
                path[20] == '\0') {
                
                // Generate SELinux POLICY RELOAD alert for denied open attempt
                if (event_chosen(SELINUX_POLICY_RELOAD_ALERT)) {
                    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
                    if (submit_p != NULL) {
                        set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));
                        context_t context = init_and_save_context(ctx, submit_p, SELINUX_POLICY_RELOAD_ALERT, 3, ret);
                        
                        u64 *policy_tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
                        if (policy_tags) {
                            u32 action = SELINUX_POLICY_OPEN_DENIED;
                            size_t bytes_written = 0;
                            
                            save_to_submit_buf(submit_p, &action, sizeof(u32), UINT_T, DEC_ARG(0, *policy_tags));
                            save_to_submit_buf(submit_p, &bytes_written, sizeof(size_t), SIZE_T_T, DEC_ARG(1, *policy_tags));
                            save_str_to_buf(submit_p, (void *)path, DEC_ARG(2, *policy_tags));
                            events_perf_submit(ctx);
                        }
                    }
                }
            }
        }
    }
    
    // SELinux Protected Resource Access Alert detection
    // Monitor open, openat, access, faccessat syscalls for sensitive path access
    if (event_chosen(SELINUX_PROTECTED_RESOURCE_ACCESS_ALERT) && 
        (id == SYS_OPENAT || id == SYS_OPEN || id == 21 || id == 269 || id == 48)) {
        // Read pathname from saved args
        // For openat: args[1] = pathname; For open/access: args[0] = pathname
        // For faccessat: args[1] = pathname
        const char *pathname;
        int flags_or_mode = 0;
        
        if (id == SYS_OPENAT) {
            pathname = (const char *)saved_args.args[1];
            flags_or_mode = (int)saved_args.args[2]; // flags
        } else if (id == SYS_OPEN) {
            pathname = (const char *)saved_args.args[0];
            flags_or_mode = (int)saved_args.args[1]; // flags
        } else if (id == 21) { // access
            pathname = (const char *)saved_args.args[0];
            flags_or_mode = (int)saved_args.args[1]; // mode
        } else if (id == 269 || id == 48) { // faccessat (x86_64: 269, arm64: 48)
            pathname = (const char *)saved_args.args[1];
            flags_or_mode = (int)saved_args.args[2]; // mode
        } else {
            pathname = (const char *)saved_args.args[0];
        }
        
        // Check for sensitive path match
        char matched_prefix[32] = {0};
        char path_buf[64] = {0};
        bpf_probe_read_str(path_buf, sizeof(path_buf), pathname);
        
        int path_type = get_sensitive_path_type(path_buf, matched_prefix);
        
        if (path_type != SENSITIVE_PATH_NONE) {
            // Determine access type based on syscall and flags
            u32 access_type = ACCESS_TYPE_UNKNOWN;
            
            if (id == SYS_OPEN || id == SYS_OPENAT) {
                // O_RDONLY=0, O_WRONLY=1, O_RDWR=2
                int access_mode = flags_or_mode & 3;
                if (access_mode == 0) {
                    access_type = ACCESS_TYPE_READ;
                } else if (access_mode == 1) {
                    access_type = ACCESS_TYPE_WRITE;
                } else if (access_mode == 2) {
                    access_type = ACCESS_TYPE_WRITE; // Read+Write, report as write
                }
            } else if (id == 21 || id == 269 || id == 48) {
                // access/faccessat: check mode bits
                // R_OK=4, W_OK=2, X_OK=1, F_OK=0
                if (flags_or_mode & 0x02) {
                    access_type = ACCESS_TYPE_WRITE;
                } else if (flags_or_mode & 0x01) {
                    access_type = ACCESS_TYPE_EXECUTE;
                } else if (flags_or_mode & 0x04) {
                    access_type = ACCESS_TYPE_READ;
                } else {
                    access_type = ACCESS_TYPE_STAT; // F_OK check
                }
            }
            
            // Determine result (allowed or denied)
            u32 result = (ret >= 0) ? ACCESS_RESULT_ALLOWED : ACCESS_RESULT_DENIED;
            
            // Get syscall name
            char syscall_name[16] = {0};
            get_syscall_name(id, syscall_name);
            
            // Submit alert
            buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
            if (submit_p != NULL) {
                set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));
                context_t context = init_and_save_context(ctx, submit_p, SELINUX_PROTECTED_RESOURCE_ACCESS_ALERT, 7, ret);
                
                u64 *alert_tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
                if (alert_tags) {
                    int retval_int = (int)ret;
                    
                    // Args: syscall_name, pathname, matched_prefix, access_type, flags_or_mode, retval, result
                    save_str_to_buf(submit_p, (void *)syscall_name, DEC_ARG(0, *alert_tags));
                    save_str_to_buf(submit_p, (void *)path_buf, DEC_ARG(1, *alert_tags));
                    save_str_to_buf(submit_p, (void *)matched_prefix, DEC_ARG(2, *alert_tags));
                    save_to_submit_buf(submit_p, &access_type, sizeof(u32), UINT_T, DEC_ARG(3, *alert_tags));
                    save_to_submit_buf(submit_p, &flags_or_mode, sizeof(int), INT_T, DEC_ARG(4, *alert_tags));
                    save_to_submit_buf(submit_p, &retval_int, sizeof(int), INT_T, DEC_ARG(5, *alert_tags));
                    save_to_submit_buf(submit_p, &result, sizeof(u32), UINT_T, DEC_ARG(6, *alert_tags));
                    events_perf_submit(ctx);
                }
            }
        }
    }

    if (event_chosen(id)) {
        u64 types = 0;
        u64 tags = 0;
        bool submit_event = true;
        if (id != SYS_EXECVE && id != SYS_EXECVEAT) {
            u64 *saved_types = bpf_map_lookup_elem(&params_types_map, &id);
            u64 *saved_tags = bpf_map_lookup_elem(&params_names_map, &id);
            if (!saved_types || !saved_tags) {
                return -1;
            }
            types = *saved_types;
            tags = *saved_tags;
        } else {
            // We can't use saved args after execve syscall, as pointers are invalid
            // To avoid showing execve event both on entry and exit,
            // we only output failed execs
            if (ret == 0)
                submit_event = false;
        }

        if (submit_event)
            trace_ret_generic(ctx, id, types, tags, &saved_args, ret);
    }

    // call syscall handler, if exists
    save_args(&saved_args, id);
    save_retval(ret, id);
    // exit tail calls should always delete args and retval before return
    bpf_tail_call(ctx, &sys_exit_tails, id);
    del_retval(id);
    del_args(id);
    return 0;
}

SEC("raw_tracepoint/sys_execve")
int syscall__execve(void *ctx)
{
    args_t args = {};
    u8 argnum = 0;

    bool delete_args = false;
    if (load_args(&args, delete_args, SYS_EXECVE) != 0)
        return -1;

    if (!event_chosen(SYS_EXECVE))
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, SYS_EXECVE, 2 /*argnum*/, 0 /*ret*/);

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    argnum += save_str_to_buf(submit_p, (void *)args.args[0] /*filename*/, DEC_ARG(0, *tags));
    argnum += save_str_arr_to_buf(submit_p, (const char *const *)args.args[1] /*argv*/, DEC_ARG(1, *tags));
    if (get_config(CONFIG_EXEC_ENV)) {
        argnum += save_str_arr_to_buf(submit_p, (const char *const *)args.args[2] /*envp*/, DEC_ARG(2, *tags));
    }

    context.argnum = argnum;
    save_context_to_buf(submit_p, (void*)&context);
    events_perf_submit(ctx);
    return 0;
}

SEC("raw_tracepoint/sys_execveat")
int syscall__execveat(void *ctx)
{
    args_t args = {};
    u8 argnum = 0;

    bool delete_args = false;
    if (load_args(&args, delete_args, SYS_EXECVEAT) != 0)
        return -1;

    if (!event_chosen(SYS_EXECVEAT))
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, SYS_EXECVEAT, 4 /*argnum*/, 0 /*ret*/);

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    argnum += save_to_submit_buf(submit_p, (void*)&args.args[0] /*dirfd*/, sizeof(int), INT_T, DEC_ARG(0, *tags));
    argnum += save_str_to_buf(submit_p, (void *)args.args[1] /*pathname*/, DEC_ARG(1, *tags));
    argnum += save_str_arr_to_buf(submit_p, (const char *const *)args.args[2] /*argv*/, DEC_ARG(2, *tags));
    if (get_config(CONFIG_EXEC_ENV)) {
        argnum += save_str_arr_to_buf(submit_p, (const char *const *)args.args[3] /*envp*/, DEC_ARG(3, *tags));
    }
    argnum += save_to_submit_buf(submit_p, (void*)&args.args[4] /*flags*/, sizeof(int), INT_T, DEC_ARG(4, *tags));

    context.argnum = argnum;
    save_context_to_buf(submit_p, (void*)&context);
    events_perf_submit(ctx);
    return 0;
}

/*============================== UPROBES HOOKS ==============================*/

SEC("uprobe/api_uprobe_ent")
int api_uprobe_ent_generic(struct pt_regs *ctx)
{
    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    u64 uprobe_off = PT_REGS_IP(ctx);
    //bpf_trace_printk("%llx\n", uprobe_off);

    // save uprobe_off so userspace can know which uprobe was called
    save_to_submit_buf(submit_p, (void*)&uprobe_off, sizeof(unsigned long), ULONG_T, 0);
    u8 argnum = 1;


/*
// API uprobes are not supported yet, as this requires composing java classes from memory
    u64 *types_p = bpf_map_lookup_elem(&types_map, &uprobe_off);
    if (types_p == NULL)
        return 0;
    u64 types = *types_p;

    u32 args_off = 8;

    #pragma unroll
    for (int i = 0; i < 6; i++) {
        void *arg_p = (void *)(READ_KERN(ctx->sp) + args_off);
        u8 type = DEC_ARG(i, types);
        u8 type_size = 4;
        if (type != NONE_T)
            argnum += save_to_submit_buf(submit_p, arg_p, type_size, UINT_T, 0);
        args_off += type_size;
    }
*/
    init_and_save_context(ctx, submit_p, GENERIC_API_UPROBE, argnum, 0);

    events_perf_submit(ctx);
    return 0;
}

SEC("uprobe/func_uprobe_ent")
int func_trace_ent_generic(struct pt_regs *ctx)
{
    if (!should_trace())
        return 0;

    save_args_from_regs(ctx, GENERIC_UPROBE, false);
    u64 uprobe_off = PT_REGS_IP(ctx);
    //bpf_trace_printk("%llx\n", uprobe_off);

    u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&uprobe_off_map, &id, &uprobe_off, BPF_ANY);
    return 0;
}

SEC("uprobe/func_uprobe_ret")
int func_trace_ret_generic(struct pt_regs *ctx)
{
    args_t args = {};
    u64 *off_p;
    u64 uprobe_off;
    u64 id = bpf_get_current_pid_tgid();

    off_p = bpf_map_lookup_elem(&uprobe_off_map, &id);
    if (off_p == 0) {
        return -1;
    }

    bpf_map_delete_elem(&uprobe_off_map, &id);

    uprobe_off = *off_p;

    if (!should_trace())
        return 0;

    u64 *types_p = bpf_map_lookup_elem(&types_map, &uprobe_off);
    if (types_p == NULL)
        return 0;
    u64 types = *types_p;

    bool delete_args = true;
    if (load_args(&args, delete_args, GENERIC_UPROBE) != 0)
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    // save uprobe_off so userspace can know which uprobe was called
    save_to_submit_buf(submit_p, &uprobe_off, sizeof(unsigned long), ULONG_T, 0);
    u8 argnum = save_args_to_submit_buf(types, types, &args) + 1;
    init_and_save_context(ctx, submit_p, GENERIC_UPROBE, argnum, PT_REGS_RC(ctx));

    events_perf_submit(ctx);
    return 0;
}

/*============================== OTHER HOOKS ==============================*/

SEC("raw_tracepoint/sched_process_exit")
int tracepoint__sched__sched_process_exit(
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
void *ctx
#else
struct bpf_raw_tracepoint_args *ctx
#endif
)
{
    if (!should_trace())
        return 0;

    u32 pid = bpf_get_current_pid_tgid();
    // Remove pid from traced_pids_map
    bpf_map_delete_elem(&traced_pids_map, &pid);

    if (get_config(CONFIG_NEW_CONT_FILTER)) {
        struct task_struct *task;
        task = (struct task_struct *)bpf_get_current_task();

        u32 pid_ns = get_task_pid_ns_id(task);
        if (get_task_ns_pid(task) == 1) {
            // If pid equals 1 - stop tracing this pid namespace
            bpf_map_delete_elem(&new_pidns_map, &pid_ns);
        }
    }
    bpf_map_delete_elem(&pid_to_uid, &pid);

    if (get_config(CONFIG_NEW_PID_FILTER)) {
        // Remove pid from new_pids_map
        bpf_map_delete_elem(&new_pids_map, &pid);
    }

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    init_and_save_context(ctx, submit_p, SCHED_PROCESS_EXIT, 0, 0);

    events_perf_submit(ctx);
    return 0;
}

SEC("kprobe/do_exit")
int BPF_KPROBE(trace_do_exit)
{
    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    long code = PT_REGS_PARM1(ctx);

    init_and_save_context(ctx, submit_p, DO_EXIT, 0, code);

    events_perf_submit(ctx);
    return 0;
}

SEC("kprobe/security_bprm_check")
int BPF_KPROBE(trace_security_bprm_check)
{
    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, SECURITY_BPRM_CHECK, 4 /*argnum*/, 0 /*ret*/);

    struct linux_binprm *bprm = (struct linux_binprm *)PT_REGS_PARM1(ctx);
    struct file* file = get_file_ptr_from_bprm(bprm);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    const char *fs_type = get_fs_type_from_file(file);

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return -1;
    save_file_path_to_str_buf(string_p, file);
    u32 *off = get_buf_off(STRING_BUF_IDX);
    if (off == NULL)
        return -1;

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    save_str_to_buf(submit_p, (void *)&string_p->buf[*off], DEC_ARG(0, *tags));
    save_to_submit_buf(submit_p, &s_dev, sizeof(dev_t), DEV_T_T, DEC_ARG(1, *tags));
    save_to_submit_buf(submit_p, &inode_nr, sizeof(unsigned long), ULONG_T, DEC_ARG(2, *tags));
    save_str_to_buf(submit_p, (void *)fs_type, DEC_ARG(3, *tags));

    events_perf_submit(ctx);
    
    // Check for setenforce command execution and generate SELinux alert
    // Note: The actual mode change will be detected via vfs_write to /sys/fs/selinux/enforce
    // This detection provides early warning that setenforce was invoked
    
    // Check binary path from bprm->file
    if (event_chosen(SELINUX_MODE_CHANGE_ALERT) && is_setenforce_cmd(&string_p->buf[*off])) {
        // Reset buffer for the SELinux alert
        set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));
        context.eventid = SELINUX_MODE_CHANGE_ALERT;
        context.argnum = 4;
        context.retval = 0;
        save_context_to_buf(submit_p, (void*)&context);
        
        u64 *selinux_tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
        if (selinux_tags) {
            // We can't easily determine the mode from command args in BPF
            // Use 0xFFFFFFFF as unknown, let userspace handle correlation
            // The actual mode will be detected from the subsequent vfs_write
            u32 unknown_mode = 0xFFFFFFFF;
            u32 method = SELINUX_METHOD_SETENFORCE;
            char empty_str[1] = {0}; // Empty string without rodata relocation
            save_to_submit_buf(submit_p, &unknown_mode, sizeof(u32), UINT_T, DEC_ARG(0, *selinux_tags));
            save_to_submit_buf(submit_p, &method, sizeof(u32), UINT_T, DEC_ARG(1, *selinux_tags));
            save_str_to_buf(submit_p, (void *)&string_p->buf[*off], DEC_ARG(2, *selinux_tags));
            save_str_to_buf(submit_p, (void *)empty_str, DEC_ARG(3, *selinux_tags)); // No value available at this point
            events_perf_submit(ctx);
        }
    }
    
    // SU/SUDO DETECTION AT security_bprm_check - catches successful executions
    // that passed SELinux checks. The path is read from kernel buffer (reliable).
    // Note: syscall entry detection (in sys_enter) catches blocked attempts.
    if (event_chosen(SU_SUDO_ALERT)) {
        int su_sudo_type = is_su_sudo_cmd(&string_p->buf[*off]);
        if (su_sudo_type > 0) {
            // Reset buffer for the su/sudo alert
            set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));
            context.eventid = SU_SUDO_ALERT;
            context.argnum = 3;
            context.retval = 0;
            save_context_to_buf(submit_p, (void*)&context);
            
            u64 *su_sudo_tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
            if (su_sudo_tags) {
                // At security_bprm_check, the execution passed SELinux -> successful
                u32 cmd_type = (u32)su_sudo_type;
                u32 result = SU_SUDO_RESULT_SUCCESSFUL;
                save_to_submit_buf(submit_p, &cmd_type, sizeof(u32), UINT_T, DEC_ARG(0, *su_sudo_tags));
                save_str_to_buf(submit_p, (void *)&string_p->buf[*off], DEC_ARG(1, *su_sudo_tags));
                save_to_submit_buf(submit_p, &result, sizeof(u32), UINT_T, DEC_ARG(2, *su_sudo_tags));
                events_perf_submit(ctx);
            }
        }
    }
    
    return 0;
}

SEC("kprobe/security_file_open")
int BPF_KPROBE(trace_security_file_open)
{
    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, SECURITY_FILE_OPEN, 4 /*argnum*/, 0 /*ret*/);

    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);

    // only monitor open and openat syscalls
    int syscall_nr = get_syscall_ev_id_from_regs();
    if (syscall_nr != SYS_OPEN && syscall_nr != SYS_OPENAT)
        return 0;

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return -1;
    save_file_path_to_str_buf(string_p, file);
    u32 *off = get_buf_off(STRING_BUF_IDX);
    if (off == NULL)
        return -1;

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    save_str_to_buf(submit_p, (void *)&string_p->buf[*off], DEC_ARG(0, *tags));
    save_to_submit_buf(submit_p, (void*)&file->f_flags, sizeof(int), INT_T, DEC_ARG(1, *tags));
    save_to_submit_buf(submit_p, &s_dev, sizeof(dev_t), DEV_T_T, DEC_ARG(2, *tags));
    save_to_submit_buf(submit_p, &inode_nr, sizeof(unsigned long), ULONG_T, DEC_ARG(3, *tags));

    events_perf_submit(ctx);
    
    // SELinux mode change attempt detection via open with write flags
    // Check if opening /sys/fs/selinux/enforce with write access
    // O_WRONLY=1, O_RDWR=2 - check if either bit is set (flags & 3) != 0 means write intent
    int f_flags = 0;
    bpf_probe_read(&f_flags, sizeof(int), &file->f_flags);
    
    if (event_chosen(SELINUX_MODE_CHANGE_ALERT) && 
        (f_flags & 3) != 0 &&  // Has write flags (O_WRONLY or O_RDWR)
        is_selinux_enforce_path(&string_p->buf[*off])) {
        
        // This is an attempt to open SELinux enforce file for writing
        // Generate alert - at this point we don't know if it will succeed or fail
        // But if it reaches vfs_write, we'll get a more detailed alert there
        // This alert is specifically for catching open attempts that may be denied
        
        set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));
        context.eventid = SELINUX_MODE_CHANGE_ALERT;
        context.argnum = 4;
        context.retval = 0;
        save_context_to_buf(submit_p, (void*)&context);
        
        u64 *selinux_tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
        if (selinux_tags) {
            // Use SELINUX_OPEN_ATTEMPT to indicate an open with write intent
            // The actual value to be written is unknown at open time
            u32 attempt_mode = SELINUX_OPEN_ATTEMPT;
            u32 method = SELINUX_METHOD_WRITE;
            char attempt_val[4] = {0, 0, 0, 0}; // Unknown value at open time
            save_to_submit_buf(submit_p, &attempt_mode, sizeof(u32), UINT_T, DEC_ARG(0, *selinux_tags));
            save_to_submit_buf(submit_p, &method, sizeof(u32), UINT_T, DEC_ARG(1, *selinux_tags));
            save_str_to_buf(submit_p, (void *)&string_p->buf[*off], DEC_ARG(2, *selinux_tags));
            save_str_to_buf(submit_p, (void *)attempt_val, DEC_ARG(3, *selinux_tags));
            events_perf_submit(ctx);
        }
    }
    
    return 0;
}

SEC("kprobe/security_inode_unlink")
int BPF_KPROBE(trace_security_inode_unlink)
{
    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, SECURITY_INODE_UNLINK, 1 /*argnum*/, 0 /*ret*/);

    //struct inode *dir = (struct inode *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return -1;
    save_dentry_path_to_str_buf(string_p, dentry);
    u32 *off = get_buf_off(STRING_BUF_IDX);
    if (off == NULL)
        return -1;

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    save_str_to_buf(submit_p, (void *)&string_p->buf[*off], DEC_ARG(0, *tags));

    events_perf_submit(ctx);
    return 0;
}

SEC("kprobe/cap_capable")
int BPF_KPROBE(trace_cap_capable)
{
    int audit;

    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, CAP_CAPABLE, 1 /*argnum*/, 0 /*ret*/);

    //const struct cred *cred = (const struct cred *)PT_REGS_PARM1(ctx);
    //struct user_namespace *targ_ns = (struct user_namespace *)PT_REGS_PARM2(ctx);
    int cap = PT_REGS_PARM3(ctx);
    int cap_opt = PT_REGS_PARM4(ctx);

  #ifdef CAP_OPT_NONE
    audit = (cap_opt & 0b10) == 0;
  #else
    audit = cap_opt;
  #endif

    if (audit == 0)
        return 0;

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    save_to_submit_buf(submit_p, (void*)&cap, sizeof(int), INT_T, DEC_ARG(0, *tags));
    if (get_config(CONFIG_SHOW_SYSCALL)) {
        int syscall_nr = get_syscall_ev_id_from_regs();
        if (syscall_nr >= 0) {
            context.argnum++;
            save_context_to_buf(submit_p, (void*)&context);
            save_to_submit_buf(submit_p, (void*)&syscall_nr, sizeof(int), INT_T, DEC_ARG(1, *tags));
        }
    }
    events_perf_submit(ctx);
    return 0;
};

SEC("kprobe/send_bin")
int BPF_KPROBE(send_bin)
{
    // Note: sending the data to the userspace have the following constraints:
    // 1. We need a buffer that we know it's exact size (so we can send chunks of known sizes in BPF)
    // 2. We can have multiple cpus - need percpu array
    // 3. We have to use perf submit and not maps as data can be overriden if userspace doesn't consume it fast enough

    int i = 0;
    unsigned int chunk_size;
    u64 id = bpf_get_current_pid_tgid();

    bin_args_t *bin_args_p = bpf_map_lookup_elem(&bin_args_map, &id);
    if (bin_args_p == 0) {
        // missed entry or not traced
        return 0;
    }

    bin_args_t bin_args;
    bpf_probe_read(&bin_args, sizeof(bin_args_t), bin_args_p);

    if (bin_args.full_size <= 0) {
        // If there are more vector elements, continue to the next one
        bin_args.iov_idx++;
        if (bin_args.iov_idx < bin_args.iov_len) {
            // Handle the rest of the write recursively
            struct iovec io_vec;
            bpf_probe_read(&io_vec, sizeof(struct iovec), &bin_args.vec[bin_args.iov_idx]);
            bin_args.ptr = io_vec.iov_base;
            bin_args.full_size = io_vec.iov_len;
            bpf_map_update_elem(&bin_args_map, &id, &bin_args, BPF_ANY);
            bpf_tail_call(ctx, &prog_array, TAIL_SEND_BIN);
        }
        bpf_map_delete_elem(&bin_args_map, &id);
        return 0;
    }

    buf_t *file_buf_p = get_buf(FILE_BUF_IDX);
    if (file_buf_p == NULL) {
        bpf_map_delete_elem(&bin_args_map, &id);
        return 0;
    }

#define F_SEND_TYPE   0
#define F_MNT_NS      (F_SEND_TYPE + sizeof(u8))
#define F_META_OFF    (F_MNT_NS + sizeof(u32))
#define F_SZ_OFF      (F_META_OFF + SEND_META_SIZE)
#define F_POS_OFF     (F_SZ_OFF + sizeof(unsigned int))
#define F_CHUNK_OFF   (F_POS_OFF + sizeof(off_t))
#define F_CHUNK_SIZE  (MAX_PERCPU_BUFSIZE >> 1)

    bpf_probe_read((void **)&(file_buf_p->buf[F_SEND_TYPE]), sizeof(u8), &bin_args.type);

    u32 mnt_id = get_task_mnt_ns_id((struct task_struct *)bpf_get_current_task());
    bpf_probe_read((void **)&(file_buf_p->buf[F_MNT_NS]), sizeof(u32), &mnt_id);

    // Save metadata to be used in filename
    bpf_probe_read((void **)&(file_buf_p->buf[F_META_OFF]), SEND_META_SIZE, bin_args.metadata);

    // Save number of written bytes. Set this to CHUNK_SIZE for full chunks
    chunk_size = F_CHUNK_SIZE;
    bpf_probe_read((void **)&(file_buf_p->buf[F_SZ_OFF]), sizeof(unsigned int), &chunk_size);

    unsigned int full_chunk_num = bin_args.full_size/F_CHUNK_SIZE;
    void *data = file_buf_p->buf;

    // Handle full chunks in loop
    #pragma unroll
    for (i = 0; i < 110; i++) {
        // Dummy instruction, as break instruction can't be first with unroll optimization
        chunk_size = F_CHUNK_SIZE;

        if (i == full_chunk_num)
            break;

        // Save binary chunk and file position of write
        bpf_probe_read((void **)&(file_buf_p->buf[F_POS_OFF]), sizeof(off_t), &bin_args.start_off);
        bpf_probe_read((void **)&(file_buf_p->buf[F_CHUNK_OFF]), F_CHUNK_SIZE, bin_args.ptr);
        bin_args.ptr += F_CHUNK_SIZE;
        bin_args.start_off += F_CHUNK_SIZE;

        bpf_perf_event_output(ctx, &file_writes, BPF_F_CURRENT_CPU, data, F_CHUNK_OFF+F_CHUNK_SIZE);
    }

    chunk_size = bin_args.full_size - i*F_CHUNK_SIZE;

    if (chunk_size > F_CHUNK_SIZE) {
        // Handle the rest of the write recursively
        bin_args.full_size = chunk_size;
        bpf_map_update_elem(&bin_args_map, &id, &bin_args, BPF_ANY);
        bpf_tail_call(ctx, &prog_array, TAIL_SEND_BIN);
        bpf_map_delete_elem(&bin_args_map, &id);
        return 0;
    }

    // Save last chunk
    chunk_size = ((chunk_size - 1) & ((MAX_PERCPU_BUFSIZE >> 1) - 1)) + 1;
    bpf_probe_read((void **)&(file_buf_p->buf[F_CHUNK_OFF]), chunk_size, bin_args.ptr);
    bpf_probe_read((void **)&(file_buf_p->buf[F_SZ_OFF]), sizeof(unsigned int), &chunk_size);
    bpf_probe_read((void **)&(file_buf_p->buf[F_POS_OFF]), sizeof(off_t), &bin_args.start_off);

    // Satisfy validator by setting buffer bounds
    int size = ((F_CHUNK_OFF+chunk_size-1) & (MAX_PERCPU_BUFSIZE - 1)) + 1;
    bpf_perf_event_output(ctx, &file_writes, BPF_F_CURRENT_CPU, data, size);

    // We finished writing an element of the vector - continue to next element
    bin_args.iov_idx++;
    if (bin_args.iov_idx < bin_args.iov_len) {
        // Handle the rest of the write recursively
        struct iovec io_vec;
        bpf_probe_read(&io_vec, sizeof(struct iovec), &bin_args.vec[bin_args.iov_idx]);
        bin_args.ptr = io_vec.iov_base;
        bin_args.full_size = io_vec.iov_len;
        bpf_map_update_elem(&bin_args_map, &id, &bin_args, BPF_ANY);
        bpf_tail_call(ctx, &prog_array, TAIL_SEND_BIN);
    }

    bpf_map_delete_elem(&bin_args_map, &id);
    return 0;
}

static __always_inline int do_vfs_write_writev(struct pt_regs *ctx, u32 event_id, u32 tail_call_id)
{
    args_t saved_args;
    bool has_filter = false;
    bool filter_match = false;

    bool delete_args = false;
    if (load_args(&saved_args, delete_args, event_id) != 0) {
        // missed entry or not traced
        return 0;
    }

    struct file *file      = (struct file *) saved_args.args[0];

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return -1;
    save_file_path_to_str_buf(string_p, file);
    u32 *off = get_buf_off(STRING_BUF_IDX);
    if (off == NULL)
        return -1;

    // Check if capture write was requested for this path
    #pragma unroll
    for (int i = 0; i < 3; i++) {
        int idx = i;
        path_filter_t *filter_p = bpf_map_lookup_elem(&file_filter, &idx);
        if (filter_p == NULL)
            return -1;

        if (!filter_p->path[0])
            break;

        has_filter = true;

        if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE)
            break;

        if (has_prefix(filter_p->path, &string_p->buf[*off], MAX_PATH_PREF_SIZE)) {
            filter_match = true;
            break;
        }
    }

    // Submit vfs_write(v) event if it was chosen, or in case of a filter match (so we can get written_files metadata)
    if (event_chosen(VFS_WRITE) || event_chosen(VFS_WRITEV) || filter_match) {
        loff_t start_pos;
        size_t count;
        unsigned long vlen;

        buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
        if (submit_p == NULL)
            return 0;
        set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

        init_and_save_context(ctx, submit_p, event_id, 5 /*argnum*/, PT_REGS_RC(ctx));

        if (event_id == VFS_WRITE) {
            count              = (size_t)        saved_args.args[2];
        } else {
            vlen               =                 saved_args.args[2];
        }
        loff_t *pos            = (loff_t*)       saved_args.args[3];

        // Extract device id, inode number, and pos (offset)
        dev_t s_dev = get_dev_from_file(file);
        unsigned long inode_nr = get_inode_nr_from_file(file);
        bpf_probe_read(&start_pos, sizeof(off_t), pos);

        // Calculate write start offset
        if (start_pos != 0)
            start_pos -= PT_REGS_RC(ctx);

        u64 *tags = bpf_map_lookup_elem(&params_names_map, &event_id);
        if (!tags) {
            return -1;
        }

        save_str_to_buf(submit_p, (void *)&string_p->buf[*off], DEC_ARG(0, *tags));
        save_to_submit_buf(submit_p, &s_dev, sizeof(dev_t), DEV_T_T, DEC_ARG(1, *tags));
        save_to_submit_buf(submit_p, &inode_nr, sizeof(unsigned long), ULONG_T, DEC_ARG(2, *tags));

        if (event_id == VFS_WRITE)
            save_to_submit_buf(submit_p, &count, sizeof(size_t), SIZE_T_T, DEC_ARG(3, *tags));
        else
            save_to_submit_buf(submit_p, &vlen, sizeof(unsigned long), ULONG_T, DEC_ARG(3, *tags));
        save_to_submit_buf(submit_p, &start_pos, sizeof(off_t), OFF_T_T, DEC_ARG(4, *tags));

        // Submit vfs_write(v) event
        events_perf_submit(ctx);
    }

    if (has_filter && !filter_match) {
        // There is a filter, but no match
        del_args(event_id);
        return 0;
    }

    // No filter was given, or filter match - continue
    bpf_tail_call(ctx, &prog_array, tail_call_id);
    return 0;
}

static __always_inline int do_vfs_write_writev_tail(struct pt_regs *ctx, u32 event_id)
{
    args_t saved_args;
    bin_args_t bin_args = {};
    loff_t start_pos;

    void *ptr;
    size_t count;
    struct iovec *vec;
    unsigned long vlen;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = {};
    init_context(&context);

    bool delete_args = true;
    if (load_args(&saved_args, delete_args, event_id) != 0) {
        // missed entry or not traced
        return 0;
    }

    struct file *file      = (struct file *) saved_args.args[0];
    if (event_id == VFS_WRITE) {
        ptr                = (void*)         saved_args.args[1];
        count              = (size_t)        saved_args.args[2];
    } else {
        vec                = (struct iovec*) saved_args.args[1];
        vlen               =                 saved_args.args[2];
    }
    loff_t *pos            = (loff_t*)       saved_args.args[3];

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return -1;
    save_file_path_to_str_buf(string_p, file);
    u32 *off = get_buf_off(STRING_BUF_IDX);
    if (off == NULL)
        return -1;

    // Extract device id, inode number, mode, and pos (offset)
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    unsigned short i_mode = get_inode_mode_from_file(file);
    bpf_probe_read(&start_pos, sizeof(off_t), pos);

    // Calculate write start offset
    if (start_pos != 0)
        start_pos -= PT_REGS_RC(ctx);

    if (event_id == VFS_WRITE) {
        unsigned int magic = 0;
        if ((start_pos == 0) && (count >= 4)){
            bpf_probe_read(&magic, sizeof(unsigned int), ptr);
        }
        // time for a magic
        if ((magic == 0x464c457f) || (magic == 0x04034b50) || (magic == 0x0a786564)) {
            // Alert on write of elf, dex or archive (including zip,jar,apk) files
            context.eventid = WRITE_ALERT;
            context.argnum = 4;
            context.retval = 0;
            save_context_to_buf(submit_p, (void*)&context);
            u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
            if (!tags) {
                return -1;
            }
            save_to_submit_buf(submit_p, &magic, sizeof(unsigned int), UINT_T, DEC_ARG(0, *tags));
            save_str_to_buf(submit_p, (void *)&string_p->buf[*off], DEC_ARG(1, *tags));
            save_to_submit_buf(submit_p, &s_dev, sizeof(dev_t), DEV_T_T, DEC_ARG(2, *tags));
            save_to_submit_buf(submit_p, &inode_nr, sizeof(unsigned long), ULONG_T, DEC_ARG(3, *tags));
            events_perf_submit(ctx);
        }
        
        // SELinux mode change detection via write to /sys/fs/selinux/enforce
        if (event_chosen(SELINUX_MODE_CHANGE_ALERT) && is_selinux_enforce_path(&string_p->buf[*off])) {
            // Read the value being written (should be '0' or '1')
            char written_val[4] = {0};
            // Read at most 3 bytes (use explicit mask for BPF verifier)
            // The value should be '0', '1', '0\n', or '1\n'
            bpf_probe_read(written_val, 3, ptr);
            
            // Check return value to determine if write succeeded
            // PT_REGS_RC(ctx) > 0 means success, <= 0 means failure
            long write_ret = PT_REGS_RC(ctx);
            int write_success = (write_ret > 0) ? 1 : 0;
            
            u32 new_mode = 0xFFFFFFFF; // Invalid mode
            // Check if value is '0' (permissive) or '1' (enforcing)
            if (written_val[0] == '0') {
                new_mode = write_success ? SELINUX_MODE_PERMISSIVE : SELINUX_ATTEMPT_PERMISSIVE;
            } else if (written_val[0] == '1') {
                new_mode = write_success ? SELINUX_MODE_ENFORCING : SELINUX_ATTEMPT_ENFORCING;
            }
            
            if (new_mode != 0xFFFFFFFF) {
                // Reset buffer and submit SELinux alert
                set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));
                context.eventid = SELINUX_MODE_CHANGE_ALERT;
                context.argnum = 4;
                context.retval = 0;
                save_context_to_buf(submit_p, (void*)&context);
                
                u64 *selinux_tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
                if (!selinux_tags) {
                    return -1;
                }
                
                u32 method = SELINUX_METHOD_WRITE;
                save_to_submit_buf(submit_p, &new_mode, sizeof(u32), UINT_T, DEC_ARG(0, *selinux_tags));
                save_to_submit_buf(submit_p, &method, sizeof(u32), UINT_T, DEC_ARG(1, *selinux_tags));
                save_str_to_buf(submit_p, (void *)&string_p->buf[*off], DEC_ARG(2, *selinux_tags));
                save_str_to_buf(submit_p, (void *)written_val, DEC_ARG(3, *selinux_tags));
                events_perf_submit(ctx);
            }
        }
        
        // SELinux POLICY RELOAD detection via write to /sys/fs/selinux/load
        // This is a HIGH SEVERITY security event - loading a new SELinux policy
        if (event_chosen(SELINUX_POLICY_RELOAD_ALERT) && is_selinux_load_path(&string_p->buf[*off])) {
            // Check return value to determine if write succeeded
            // PT_REGS_RC(ctx) > 0 means success (returns bytes written), <= 0 means failure
            long write_ret = PT_REGS_RC(ctx);
            u32 action = (write_ret > 0) ? SELINUX_POLICY_RELOAD_SUCCESS : SELINUX_POLICY_RELOAD_ATTEMPT;
            size_t bytes_written = (write_ret > 0) ? (size_t)write_ret : 0;
            
            // Reset buffer and submit SELinux policy reload alert
            set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));
            context.eventid = SELINUX_POLICY_RELOAD_ALERT;
            context.argnum = 3;
            context.retval = (int)write_ret;
            save_context_to_buf(submit_p, (void*)&context);
            
            u64 *policy_tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
            if (policy_tags) {
                save_to_submit_buf(submit_p, &action, sizeof(u32), UINT_T, DEC_ARG(0, *policy_tags));
                save_to_submit_buf(submit_p, &bytes_written, sizeof(size_t), SIZE_T_T, DEC_ARG(1, *policy_tags));
                save_str_to_buf(submit_p, (void *)&string_p->buf[*off], DEC_ARG(2, *policy_tags));
                events_perf_submit(ctx);
            }
        }
    }

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = context.pid;

    int idx = DEV_NULL_STR;
    path_filter_t *stored_str_p = bpf_map_lookup_elem(&string_store, &idx);
    if (stored_str_p == NULL)
        return -1;

    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE)
        return -1;

    // check for /dev/null
    if (!has_prefix(stored_str_p->path, &string_p->buf[*off], 10))
        pid = 0;

    if (get_config(CONFIG_CAPTURE_FILES)) {
        bin_args.type = SEND_VFS_WRITE;
        bpf_probe_read(bin_args.metadata, 4, &s_dev);
        bpf_probe_read(&bin_args.metadata[4], 8, &inode_nr);
        bpf_probe_read(&bin_args.metadata[12], 4, &i_mode);
        bpf_probe_read(&bin_args.metadata[16], 4, &pid);
        bin_args.start_off = start_pos;
        if (event_id == VFS_WRITE) {
            bin_args.ptr = ptr;
            bin_args.full_size = PT_REGS_RC(ctx);
        } else {
            bin_args.vec = vec;
            bin_args.iov_idx = 0;
            bin_args.iov_len = vlen;
            if (vlen > 0) {
                struct iovec io_vec;
                bpf_probe_read(&io_vec, sizeof(struct iovec), &vec[0]);
                bin_args.ptr = io_vec.iov_base;
                bin_args.full_size = io_vec.iov_len;
            }
        }
        bpf_map_update_elem(&bin_args_map, &id, &bin_args, BPF_ANY);

        // Send file data
        bpf_tail_call(ctx, &prog_array, TAIL_SEND_BIN);
    }
    return 0;
}

SEC("kprobe/vfs_write")
TRACE_ENT_FUNC(vfs_write, VFS_WRITE);

SEC("kretprobe/vfs_write")
int BPF_KPROBE(trace_ret_vfs_write)
{
    return do_vfs_write_writev(ctx, VFS_WRITE, TAIL_VFS_WRITE);
}

SEC("kretprobe/vfs_write_tail")
int BPF_KPROBE(trace_ret_vfs_write_tail)
{
    return do_vfs_write_writev_tail(ctx, VFS_WRITE);
}

SEC("kprobe/vfs_writev")
TRACE_ENT_FUNC(vfs_writev, VFS_WRITEV);

SEC("kretprobe/vfs_writev")
int BPF_KPROBE(trace_ret_vfs_writev)
{
    return do_vfs_write_writev(ctx, VFS_WRITEV, TAIL_VFS_WRITEV);
}

SEC("kretprobe/vfs_writev_tail")
int BPF_KPROBE(trace_ret_vfs_writev_tail)
{
    return do_vfs_write_writev_tail(ctx, VFS_WRITEV);
}

SEC("kprobe/security_mmap_addr")
int BPF_KPROBE(trace_mmap_alert)
{
    args_t args = {};

    // Arguments will be deleted on raw_syscalls_exit (with mmap syscall id)
    bool delete_args = false;
    if (load_args(&args, delete_args, SYS_MMAP) != 0)
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, MEM_PROT_ALERT, 1 /*argnum*/, 0 /*ret*/);

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    if ((args.args[2] & (VM_WRITE|VM_EXEC)) == (VM_WRITE|VM_EXEC)) {
        alert_t alert = {.ts = context.ts, .msg = ALERT_MMAP_W_X, .payload = 0};
        save_to_submit_buf(submit_p, &alert, sizeof(alert_t), ALERT_T, DEC_ARG(0, *tags));
        events_perf_submit(ctx);
    }

    return 0;
}

SEC("kprobe/security_file_mprotect")
int BPF_KPROBE(trace_mprotect_alert)
{
    args_t args = {};
    bin_args_t bin_args = {};

    // Arguments will be deleted on raw_syscalls_exit (with mprotect syscall id)
    bool delete_args = false;
    if (load_args(&args, delete_args, SYS_MPROTECT) != 0)
        return 0;

    struct vm_area_struct *vma = (struct vm_area_struct *)PT_REGS_PARM1(ctx);
    unsigned long reqprot = PT_REGS_PARM2(ctx);
    //unsigned long prot = PT_REGS_PARM3(ctx);

    void *addr = (void*)args.args[0];
    size_t len = args.args[1];
    unsigned long prev_prot = get_vma_flags(vma);

    if (addr <= 0)
        return 0;

    // If length is 0, the current page permissions are changed
    if (len == 0)
        len = PAGE_SIZE;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, MEM_PROT_ALERT, 1 /*argnum*/, 0 /*ret*/);

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    if ((!(prev_prot & VM_EXEC)) && (reqprot & VM_EXEC)) {
        alert_t alert = {.ts = context.ts, .msg = ALERT_MPROT_X_ADD, .payload = 0};
        save_to_submit_buf(submit_p, &alert, sizeof(alert_t), ALERT_T, DEC_ARG(0, *tags));
        events_perf_submit(ctx);
        return 0;
    }

    if ((prev_prot & VM_EXEC) && !(prev_prot & VM_WRITE)
        && ((reqprot & (VM_WRITE|VM_EXEC)) == (VM_WRITE|VM_EXEC))) {
        alert_t alert = {.ts = context.ts, .msg = ALERT_MPROT_W_ADD, .payload = 0};
        save_to_submit_buf(submit_p, &alert, sizeof(alert_t), ALERT_T, DEC_ARG(0, *tags));
        events_perf_submit(ctx);
        return 0;
    }

    if (((prev_prot & (VM_WRITE|VM_EXEC)) == (VM_WRITE|VM_EXEC))
        && (reqprot & VM_EXEC) && !(reqprot & VM_WRITE)) {
        alert_t alert = {.ts = context.ts, .msg = ALERT_MPROT_W_REM, .payload = 0 };
        if (get_config(CONFIG_EXTRACT_DYN_CODE)) 
            alert.payload = 1;
        save_to_submit_buf(submit_p, &alert, sizeof(alert_t), ALERT_T, DEC_ARG(0, *tags));
        events_perf_submit(ctx);

        if (get_config(CONFIG_EXTRACT_DYN_CODE)) {
            bin_args.type = SEND_MPROTECT;
            bpf_probe_read(bin_args.metadata, sizeof(u64), &context.ts);
            bin_args.ptr = (char *)addr;
            bin_args.start_off = 0;
            bin_args.full_size = len;

            u64 id = bpf_get_current_pid_tgid();
            bpf_map_update_elem(&bin_args_map, &id, &bin_args, BPF_ANY);
            bpf_tail_call(ctx, &prog_array, TAIL_SEND_BIN);
        }
    }

    return 0;
}

/*
 * IP Address Change Detection
 * 
 * These kprobes hook into the kernel's IPv4 address management functions:
 * - __inet_insert_ifa: Called when a new IPv4 address is added to an interface
 * - __inet_del_ifa: Called when an IPv4 address is removed from an interface
 *
 * Function signatures:
 *   static int __inet_insert_ifa(struct in_ifaddr *ifa, struct nlmsghdr *nlh, u32 portid)
 *   static void __inet_del_ifa(struct in_device *in_dev, struct in_ifaddr **ifap, int destroy, struct nlmsghdr *nlh, u32 portid)
 *
 * Note: IP address is sent as raw u32 in network byte order. Conversion to
 * dotted-decimal string format is done in userspace for BPF verifier compatibility.
 */

// Kprobe for __inet_insert_ifa - IPv4 address added
// Signature: static int __inet_insert_ifa(struct in_ifaddr *ifa, struct nlmsghdr *nlh, u32 portid)
SEC("kprobe/__inet_insert_ifa")
int BPF_KPROBE(trace_inet_insert_ifa)
{
    struct in_ifaddr *ifa = (struct in_ifaddr *)PT_REGS_PARM1(ctx);
    if (!ifa)
        return 0;

    // Capture netlink portid - identifies the requesting process (0 = kernel-initiated)
    u32 nl_portid = (u32)PT_REGS_PARM3(ctx);

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, IP_CHANGE_ALERT, 5 /*argnum*/, 0 /*ret*/);

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    // Action: IP_ACTION_ADD (1)
    u32 action = IP_ACTION_ADD;
    save_to_submit_buf(submit_p, &action, sizeof(u32), UINT_T, DEC_ARG(0, *tags));

    // Read IP address (send as raw u32, convert in userspace)
    u32 ip_addr = READ_KERN(ifa->ifa_local);
    save_to_submit_buf(submit_p, &ip_addr, sizeof(u32), UINT_T, DEC_ARG(1, *tags));

    // Read interface label/name
    char if_label[16] = {0};
    bpf_probe_read_str(if_label, sizeof(if_label), ifa->ifa_label);
    // If label is empty, try to get from device
    if (if_label[0] == '\0') {
        struct in_device *in_dev = READ_KERN(ifa->ifa_dev);
        if (in_dev) {
            struct net_device *dev = READ_KERN(in_dev->dev);
            if (dev) {
                bpf_probe_read_str(if_label, sizeof(if_label), dev->name);
            }
        }
    }
    save_str_to_buf(submit_p, if_label, DEC_ARG(2, *tags));

    // Read prefix length
    u8 prefixlen = READ_KERN(ifa->ifa_prefixlen);
    u32 prefixlen_32 = prefixlen;
    save_to_submit_buf(submit_p, &prefixlen_32, sizeof(u32), UINT_T, DEC_ARG(3, *tags));

    // Save netlink portid (0 = kernel/DHCP initiated, non-zero = process netlink socket PID)
    save_to_submit_buf(submit_p, &nl_portid, sizeof(u32), UINT_T, DEC_ARG(4, *tags));

    events_perf_submit(ctx);
    return 0;
}

// Kprobe for __inet_del_ifa - IPv4 address deleted
// Signature: static void __inet_del_ifa(struct in_device *in_dev, struct in_ifaddr **ifap, int destroy, struct nlmsghdr *nlh, u32 portid)
SEC("kprobe/__inet_del_ifa")
int BPF_KPROBE(trace_inet_del_ifa)
{
    struct in_device *in_dev = (struct in_device *)PT_REGS_PARM1(ctx);
    struct in_ifaddr **ifap = (struct in_ifaddr **)PT_REGS_PARM2(ctx);
    // portid is the 5th parameter
    u32 nl_portid = (u32)PT_REGS_PARM5(ctx);
    
    if (!in_dev || !ifap)
        return 0;

    struct in_ifaddr *ifa = NULL;
    bpf_probe_read(&ifa, sizeof(ifa), ifap);
    if (!ifa)
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, IP_CHANGE_ALERT, 5 /*argnum*/, 0 /*ret*/);

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    // Action: IP_ACTION_DEL (2)
    u32 action = IP_ACTION_DEL;
    save_to_submit_buf(submit_p, &action, sizeof(u32), UINT_T, DEC_ARG(0, *tags));

    // Read IP address (send as raw u32, convert in userspace)
    u32 ip_addr = READ_KERN(ifa->ifa_local);
    save_to_submit_buf(submit_p, &ip_addr, sizeof(u32), UINT_T, DEC_ARG(1, *tags));

    // Read interface label/name
    char if_label[16] = {0};
    bpf_probe_read_str(if_label, sizeof(if_label), ifa->ifa_label);
    // If label is empty, try to get from device
    if (if_label[0] == '\0') {
        struct net_device *dev = READ_KERN(in_dev->dev);
        if (dev) {
            bpf_probe_read_str(if_label, sizeof(if_label), dev->name);
        }
    }
    save_str_to_buf(submit_p, if_label, DEC_ARG(2, *tags));

    // Read prefix length
    u8 prefixlen = READ_KERN(ifa->ifa_prefixlen);
    u32 prefixlen_32 = prefixlen;
    save_to_submit_buf(submit_p, &prefixlen_32, sizeof(u32), UINT_T, DEC_ARG(3, *tags));

    // Save netlink portid (0 = kernel/DHCP initiated, non-zero = process netlink socket PID)
    save_to_submit_buf(submit_p, &nl_portid, sizeof(u32), UINT_T, DEC_ARG(4, *tags));

    events_perf_submit(ctx);
    return 0;
}

/*
 * SELinux Denial Detection
 *
 * These probes hook into security_inode_permission to detect SELinux denials.
 * - kprobe saves the arguments (inode, mask)
 * - kretprobe checks the return value; negative = denied (e.g., -EACCES, -EPERM)
 *
 * Function signature:
 *   int security_inode_permission(struct inode *inode, int mask)
 *
 * The mask contains MAY_READ (4), MAY_WRITE (2), MAY_EXEC (1), MAY_APPEND (8).
 * Return value: 0 = allowed, negative = denied
 */

// Structure to pass arguments from kprobe to kretprobe
typedef struct selinux_denial_args {
    struct inode *inode;
    int mask;
} selinux_denial_args_t;

// Map to store args between kprobe and kretprobe
BPF_HASH(selinux_denial_args_map, u64, selinux_denial_args_t);

// Kprobe entry: save arguments for later use in kretprobe
SEC("kprobe/security_inode_permission")
int BPF_KPROBE(trace_security_inode_permission)
{
    // Only process if event is chosen
    if (!event_chosen(SELINUX_DENIAL))
        return 0;

    u64 id = bpf_get_current_pid_tgid();
    
    selinux_denial_args_t args = {};
    args.inode = (struct inode *)PT_REGS_PARM1(ctx);
    args.mask = (int)PT_REGS_PARM2(ctx);
    
    bpf_map_update_elem(&selinux_denial_args_map, &id, &args, BPF_ANY);
    return 0;
}

// Kretprobe: check return value and emit event if denied
SEC("kretprobe/security_inode_permission")
int BPF_KRETPROBE(trace_ret_security_inode_permission)
{
    u64 id = bpf_get_current_pid_tgid();
    
    selinux_denial_args_t *args = bpf_map_lookup_elem(&selinux_denial_args_map, &id);
    if (!args) {
        return 0;
    }
    
    // Get return value - negative means denied
    int ret = (int)PT_REGS_RC(ctx);
    
    // Clean up map entry first
    struct inode *inode = args->inode;
    int mask = args->mask;
    bpf_map_delete_elem(&selinux_denial_args_map, &id);
    
    // Only emit event if permission was denied (ret < 0)
    if (ret >= 0) {
        return 0;
    }
    
    if (!inode) {
        return 0;
    }
    
    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, SELINUX_DENIAL, 5 /*argnum*/, ret);

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    // Get device id from inode's superblock
    struct super_block *sb = READ_KERN(inode->i_sb);
    dev_t dev = 0;
    if (sb) {
        dev = READ_KERN(sb->s_dev);
    }

    // Get inode number
    unsigned long ino = READ_KERN(inode->i_ino);

    // Save placeholder for pathname - security_inode_permission only provides inode,
    // getting the actual path is complex and unreliable from kretprobe context
    // Format: "inode:<ino>@dev:<dev>" to provide identification info
    char path_info[64] = {0};
    // Just save empty string, let userspace handle path resolution if needed
    save_str_to_buf(submit_p, path_info, DEC_ARG(0, *tags));

    // Save mask
    save_to_submit_buf(submit_p, &mask, sizeof(int), INT_T, DEC_ARG(1, *tags));

    // Save return value (error code)
    save_to_submit_buf(submit_p, &ret, sizeof(int), INT_T, DEC_ARG(2, *tags));

    // Save device id
    save_to_submit_buf(submit_p, &dev, sizeof(dev_t), DEV_T_T, DEC_ARG(3, *tags));

    // Save inode number
    save_to_submit_buf(submit_p, &ino, sizeof(unsigned long), ULONG_T, DEC_ARG(4, *tags));

    events_perf_submit(ctx);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
int KERNEL_VERSION SEC("version") = LINUX_VERSION_CODE;
