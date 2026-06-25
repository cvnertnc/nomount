#ifndef _LINUX_NOMOUNT_H
#define _LINUX_NOMOUNT_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/atomic.h>
#include <net/sock.h>
#include <net/genetlink.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif
#include <linux/jump_label.h>

#define NOMOUNT_VERSION    10
#define NOMOUNT_MAGIC1 0x4E4F4D4F /* 'NOMO' */
#define NOMOUNT_MAGIC2 0x554E5421 /* 'UNT!' */
#define NOMOUNT_HASH_BITS  12
#define NOMOUNT_UID_HASH_BITS 4
#define NM_FLAG_IS_DIR      (1 << 1)
#define NM_INO_TYPE_REAL    (1 << 0)
#define NM_INO_TYPE_VIRTUAL (1 << 1)
#define NM_INO_TYPE_DIR     (1 << 2)

static DEFINE_HASHTABLE(nomount_rules_ht,     NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(nomount_inodes_ht,    NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(nomount_basenames_ht, NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(nomount_uid_ht,       NOMOUNT_UID_HASH_BITS);
static LIST_HEAD(nomount_rules_list);
static LIST_HEAD(nomount_private_dirs_list);
static DEFINE_MUTEX(nomount_write_mutex);

/* logs */
#define nm_debug(fmt, ...) printk(KERN_DEBUG "NoMount: [DEBUG] " fmt, ##__VA_ARGS__)
#define nm_info(fmt, ...) printk(KERN_INFO "NoMount: " fmt, ##__VA_ARGS__)
#define nm_warn(fmt, ...) printk(KERN_WARNING "NoMount: [WARN] " fmt, ##__VA_ARGS__)
#define nm_err(fmt, ...)  printk(KERN_ERR "NoMount: [ERROR] " fmt, ##__VA_ARGS__)

struct nomount_reboot_payload {
    char virtual_path[PATH_MAX];
    char real_path[PATH_MAX];
    u32 flags;
    u32 uid;
};

struct nm_inode_node {
    struct hlist_node node;
    unsigned long ino;
    dev_t dev;
    u8 type;
    u16 len;
};

struct nomount_child_name {
    unsigned long fake_ino;
    u16 name_len;
    u8 d_type;
    char name[256];
};

struct nm_child_array {
    atomic_t refcnt;
    u32 num_children;
    struct rcu_head rcu;
    struct nomount_child_name entries[]; /* Flexible array member */
};

struct nomount_dir_node {
    struct nm_inode_node dir;
    struct list_head private_list;
    struct nm_child_array __rcu *child_array; 
    char *dir_path;
    bool is_private;
};

struct nomount_rule {
    struct list_head list;
    struct nm_inode_node real_node; 
    struct nm_inode_node virt_node;
    struct hlist_node vpath_node;
    struct hlist_node basename_node;
    struct nomount_dir_node *parent_dir;
    char *virtual_path;
    char *real_path;
    const char *basename;
    u32 v_fs_type;
    u32 v_hash;
    u32 b_hash;
    u16 b_len;
    u8  flags;
};

struct nomount_uid_node {
    struct hlist_node node;
    uid_t uid;
};

/* Commands */
enum {
    NOMOUNT_CMD_GET_VERSION = 1,
    NOMOUNT_CMD_ADD_RULE,
    NOMOUNT_CMD_DEL_RULE,
    NOMOUNT_CMD_CLEAR_ALL,
    NOMOUNT_CMD_ADD_UID,
    NOMOUNT_CMD_DEL_UID,
    NOMOUNT_CMD_GET_LIST,
};

/* Application UID start */
#define AID_APP_START 10000

/* ================================= */
/* Backend definitions and helpers   */
/* ================================= */

// LKM-specific includes
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/module.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t nm_kallsyms;

static int nm_resolve_kallsyms(void) {
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    int ret = register_kprobe(&kp);
    if (ret < 0) return ret;
    nm_kallsyms = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    return 0;
}
#else
#define nm_kallsyms(name) kallsyms_lookup_name(name)
#endif

struct nm_hook {
    const char *name;
    void *hook_fn;
    void *orig_fn;
    unsigned long address;

#ifdef NM_BACKEND_FTRACE
    struct ftrace_ops ops;
#else
    struct kprobe kp;
#endif
};

static int nm_resolve_hook_address(struct nm_hook *hook)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
    if (!nm_kallsyms) {
        if (nm_resolve_kallsyms()) return -ENOENT;
    }
#endif

    hook->address = nm_kallsyms(hook->name);
    if (!hook->address) {
        nm_err("Unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

    *((unsigned long*) hook->orig_fn) = hook->address;
    return 0;
}

#ifdef __x86_64__
    #define PT_REGS_IP(regs) ((regs)->ip)
#else
    #define PT_REGS_IP(regs) ((regs)->pc)
#endif

/* MCOUNT/FTRACE instruction size */
#ifdef __x86_64__
    #define MCOUNT_INSN_SIZE 5
#else
    #define MCOUNT_INSN_SIZE 4
#endif

#if defined(NM_BACKEND_FTRACE)

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define ftrace_regs pt_regs
static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
    return fregs;
}
#endif

static void notrace nm_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                     struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct nm_hook *hook = container_of(ops, struct nm_hook, ops);
    *((unsigned long*) hook->orig_fn) = ip + MCOUNT_INSN_SIZE;
    PT_REGS_IP(regs) = (unsigned long)hook->hook_fn;
}

static int nm_install_hook(struct nm_hook *hook) {
    int ret = nm_resolve_hook_address(hook);
    if (ret) return ret;

    hook->ops.func = nm_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;

    ret = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (ret) return ret;

    ret = register_ftrace_function(&hook->ops);
    if (ret) ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
  
    return ret;
}

static void nm_remove_hook(struct nm_hook *hook) {
    unregister_ftrace_function(&hook->ops);
    ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
}

#elif defined(NM_BACKEND_KPROBES)

static int notrace nm_kprobe_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct nm_hook *hook = container_of(p, struct nm_hook, kp);

#if defined(__aarch64__)
    if (p->ainsn.api.insn) *((unsigned long*) hook->orig_fn) = (unsigned long)p->ainsn.api.insn;
    else *((unsigned long*) hook->orig_fn) = (unsigned long)p->addr + MCOUNT_INSN_SIZE;
#else
    if (p->ainsn.insn) *((unsigned long*) hook->orig_fn) = (unsigned long)p->ainsn.insn;
    else *((unsigned long*) hook->orig_fn) = (unsigned long)p->addr + MCOUNT_INSN_SIZE;
#endif

    PT_REGS_IP(regs) = (unsigned long)hook->hook_fn;
    return 1;
}
NOKPROBE_SYMBOL(nm_kprobe_pre_handler);

static int nm_install_hook(struct nm_hook *hook) {
    int ret = nm_resolve_hook_address(hook);
    if (ret) return ret;

    memset(&hook->kp, 0, sizeof(struct kprobe));
    hook->kp.addr = (kprobe_opcode_t *)hook->address;
    hook->kp.pre_handler = nm_kprobe_pre_handler;

    return register_kprobe(&hook->kp);
}

static void nm_remove_hook(struct nm_hook *hook) {
    unregister_kprobe(&hook->kp);
}

#else
# error "You need dynamic ftrace or kprobes enabled in your kernel"
#endif

#endif /* _LINUX_NOMOUNT_H */
