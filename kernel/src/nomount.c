#include <linux/init.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/statfs.h>
#include <linux/fs_struct.h>
#include <linux/version.h>
#include "nomount.h"

static u64 nm_basename_filter __read_mostly ____cacheline_aligned = 0;
static struct kmem_cache *nm_rule_cachep __read_mostly, *nm_dir_cachep __read_mostly, *nm_uid_cachep __read_mostly;
atomic_t nm_active_rules = ATOMIC_INIT(0);
atomic_t nm_active_dirs = ATOMIC_INIT(0);
atomic_t nm_active_uids = ATOMIC_INIT(0);
DEFINE_STATIC_KEY_FALSE(nomount_active_rules);
DEFINE_STATIC_KEY_FALSE(nomount_active_dirs);
DEFINE_STATIC_KEY_FALSE(nomount_active_uids);


/*** Verification & Compatibility Checks ***/

/**
 * nomount_is_uid_blocked - Check if a specific UID is excluded from redirection
 * @uid: The User ID to check
 *
 * Returns true if the UID exists in the exclusion hash table.
 */
static __always_inline bool nomount_is_uid_blocked(uid_t uid) {
    struct nomount_uid_node *entry;
    rcu_read_lock();
    hash_for_each_possible_rcu(nomount_uid_ht, entry, node, uid) {
        if (entry->uid == uid) {
            rcu_read_unlock();
            return true;
        }
    }
    rcu_read_unlock();
    return false;
}

/**
 * __nomount_should_skip - Determine if the current context should bypass hooks
 *
 * Returns true if NoMount is disabled, if running in interrupt context,
 * if recursion is detected, or if the current UID is in the blocklist.
 */
static __always_inline bool __nomount_should_skip(void) {
    if (!static_branch_unlikely(&nomount_active_rules)) return true;
    if (unlikely(in_interrupt() || oops_in_progress)) return true;
    if (unlikely(current->flags & (PF_KTHREAD | PF_EXITING))) return true;
    if (unlikely(static_branch_unlikely(&nomount_active_uids))) {
        if (unlikely(nomount_is_uid_blocked(current_uid().val))) return true;
    }
    return false;
}

/*** Helpers & Path Resolution ***/

/**
 * __nomount_is_injected_file_rcu - Check if an inode number belongs to an injected file.
 * @inode: The inode to check
 *
 * This function performs a lockless check against the registered rules to determine
 * if the given inode corresponds to an injected file.
 * It checks both real and virtual inode hash tables.
 *
 * NOTE: The caller MUST hold rcu_read_lock() before calling this function
 * and keep it held as long as the result is being used.
 */
static __always_inline bool __nomount_is_injected_file_rcu(struct inode *inode) {
    struct nm_inode_node *node;
    hash_for_each_possible_rcu(nomount_inodes_ht, node, node, inode->i_ino) {
        if (node->ino == inode->i_ino && node->dev == inode->i_sb->s_dev) {
            if (node->type & (NM_INO_TYPE_REAL | NM_INO_TYPE_VIRTUAL))
                return true;
        }
    }
    return false;
}

/**
 * __nomount_is_traversal_allowed_rcu - Check if an inode number corresponds to a 
 * directory with traversal permissions
 * @inode: The inode to check
 *
 * This function checks if the given inode corresponds to a directory that allows traversal.
 *
 * NOTE: The caller MUST hold rcu_read_lock() before calling this function
 * and keep it held as long as the result is being used.
 */
static __always_inline bool __nomount_is_traversal_allowed_rcu(struct inode *inode) {
    struct nm_inode_node *node;
    hash_for_each_possible_rcu(nomount_inodes_ht, node, node, inode->i_ino) {
        if (node->ino == inode->i_ino && node->dev == inode->i_sb->s_dev) {
            if (likely(node->type & NM_INO_TYPE_DIR)) return true;
            break;
        }
    }
    return false;
}

/**
 * nomount_build_path_from_pwd - Construct an absolute path using the current working directory
 * @rel_name: The relative filename to append to the current working directory
 * @name_len: The length of the relative filename
 * @out_len: Pointer to receive the length of the constructed path
 * @out_path: Pointer to receive the allocated path string
 * @fast_buf: Pointer to a pre-allocated stack buffer for fast path resolution
 *
 * This helper is used to reconstruct an absolute path for operations that provide
 * a relative filename without a DFD, ensuring that NoMount can still resolve the intended target.
 *
 * This helper uses a fast stack buffer for common path sizes.
 * If the path exceeds the fast buffer, it allocates a full page from names_cache.
 * Returns a pointer to the buffer holding the path (fast_buf or a new page).
 * If a new page is returned, it must be freed with __putname().
 */
static const char *nomount_build_path_from_pwd(const char *rel_name, size_t name_len, size_t *out_len,
                                                const char **out_path, char *fast_buf) 
{
    struct path pwd;
    char *end_ptr, *cwd_str, *page_buf = fast_buf;
    size_t dir_len;

    rcu_read_lock();
    pwd = current->fs->pwd;
    path_get(&pwd);
    rcu_read_unlock();
    cwd_str = d_path(&pwd, page_buf, 512);

    if (IS_ERR(cwd_str)) {
        if (PTR_ERR(cwd_str) == -ENAMETOOLONG) {
            page_buf = __getname();
            if (unlikely(!page_buf)) { path_put(&pwd); return NULL; }
            cwd_str = d_path(&pwd, page_buf, PATH_MAX);
            if (IS_ERR(cwd_str)) { __putname(page_buf); path_put(&pwd); return NULL; }
        } else {
            path_put(&pwd);
            return NULL;
        }
    }
    path_put(&pwd);

    dir_len = strlen(cwd_str);
    if (likely(dir_len + name_len + 2 <= (page_buf != fast_buf ? PATH_MAX : 512))) {
        if (cwd_str != page_buf) {
            memmove(page_buf, cwd_str, dir_len);
            cwd_str = page_buf;
        }
        end_ptr = cwd_str + dir_len;
        if (dir_len > 0 && *(end_ptr - 1) != '/') { *end_ptr = '/'; end_ptr++; dir_len++; }
        memcpy(end_ptr, rel_name, name_len + 1);
        if (out_len) *out_len = dir_len + name_len;
        *out_path = cwd_str;
        return page_buf;
    }

    if (page_buf != fast_buf) __putname(page_buf);
    return NULL;
}

/**
 * nomount_get_rule_by_inode - Look up the registered rule for an inode
 * @inode: The inode to query
 *
 * NOTE: The caller MUST hold rcu_read_lock() before calling this function
 * and keep it held as long as the returned rule is being used.
 */
static __always_inline struct nomount_rule *nomount_get_rule_by_inode(struct inode *inode) {
    struct nm_inode_node *inode_node;
    hash_for_each_possible_rcu(nomount_inodes_ht, inode_node, node, inode->i_ino) {
        if (inode_node->ino == inode->i_ino && inode_node->dev == inode->i_sb->s_dev) {
            switch (inode_node->type) {
                case NM_INO_TYPE_REAL:
                    return container_of(inode_node, struct nomount_rule, real_node);
                case NM_INO_TYPE_VIRTUAL:
                    return container_of(inode_node, struct nomount_rule, virt_node);
            }
        }
    }
    return NULL;
}

/**
 * nomount_get_rule_by_path - Look up the rule for a virtual path
 * @pathname: The requested virtual path
 * @len: The length of the requested path
 *
 * Performs a fast hash lookup to find redirection rules.
 * Returns a pointer to the rule, or NULL if no rule matches.
 *
 * NOTE: The caller MUST hold rcu_read_lock() before calling this function
 * and keep it held as long as the returned rule is being used.
 */
static __always_inline struct nomount_rule *nomount_get_rule_by_path(const char *pathname, size_t len) {
    struct nomount_rule *rule;
    u32 hash = full_name_hash(NULL, pathname, len);
    hash_for_each_possible_rcu(nomount_rules_ht, rule, vpath_node, hash) {
        if (rule->v_hash == hash && rule->virt_node.len == len &&
             memcmp(pathname, rule->virtual_path, len) == 0) {
            return rule;
        }
    }
    return NULL;
}

/**
 * __nomount_rebuild_basename_filter - Rebuilds the global basename Bloom filter
 *
 * Recalculates the 64-bit fast-rejection filter by iterating over all active rules.
 * This filter maps the first character of each rule's basename into a 64-bit mask,
 * allowing the VFS hot-path to instantly reject ~80% of unmanaged paths in O(1) time
 * without acquiring RCU locks or computing full string hashes.
 *
 * NOTE: The caller MUST hold the nomount_write_mutex before calling this function
 * to prevent concurrent list modifications.
 */
static void __nomount_rebuild_basename_filter(void)
{
    struct nomount_rule *rule;
    u64 new_filter = 0;
    list_for_each_entry(rule, &nomount_rules_list, list) {
        if (likely(rule->basename && rule->b_len > 0)) {
            new_filter |= (1ULL << (rule->basename[0] & 63));
        }
    }
    WRITE_ONCE(nm_basename_filter, new_filter);
}

/*** VFS Hooks & Injection Logic ***/

/* --- 1. d_path Hook --- */
typedef char *(*d_path_t)(const struct path *, char *, int);
static d_path_t orig_d_path;

static char *hook_d_path(const struct path *path, char *buf, int buflen) {
    struct nomount_rule *rule;
    char *res; int len;

    if (!__nomount_should_skip() && !IS_ERR_OR_NULL(path) && path->dentry && path->dentry->d_inode) {
        rcu_read_lock();
        rule = nomount_get_rule_by_inode(path->dentry->d_inode);
        if (likely(rule)) {
            len = rule->virt_node.len;
            if (likely(buflen >= len + 1)) {
                res = buf + buflen - len - 1;
                memcpy(res, rule->virtual_path, len + 1);
                nm_debug("d_path spoofed %s to %s\n", rule->real_path, rule->virtual_path);
                rcu_read_unlock();
                return res; 
            }
        }
        rcu_read_unlock();
    }
    return orig_d_path(path, buf, buflen);
}

/* --- 2. Permission Hooks --- */
static int nomount_handle_permission(struct inode *inode, int mask) {
    bool is_injected = false, is_dir = false;

    if (__nomount_should_skip() || IS_ERR_OR_NULL(inode)) return 0;

    rcu_read_lock();
    is_injected = __nomount_is_injected_file_rcu(inode);
    if (!is_injected && likely(S_ISDIR(inode->i_mode))) {
        is_dir = __nomount_is_traversal_allowed_rcu(inode);
    }
    rcu_read_unlock();

    if (is_dir && !is_injected) {
        if (mask & (MAY_READ | MAY_WRITE | MAY_APPEND)) return 0;
        if (mask & MAY_EXEC) return 1;
    }

    if (is_injected) {
        if (mask & (MAY_WRITE | MAY_APPEND)) return 0;
        return 1; 
    }

    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
    #define PERM_ARGS struct mnt_idmap *idmap, struct inode *inode, int mask
    #define PERM_CALL idmap, inode, mask
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    #define PERM_ARGS struct user_namespace *mnt_userns, struct inode *inode, int mask
    #define PERM_CALL mnt_userns, inode, mask
#else
    #define PERM_ARGS struct inode *inode, int mask
    #define PERM_CALL inode, mask
#endif

typedef int (*permission_t)(PERM_ARGS);

static permission_t orig_generic_permission;
static int hook_generic_permission(PERM_ARGS) {
    int nm_perm = nomount_handle_permission(inode, mask);
    if (unlikely(nm_perm < 0)) return nm_perm;
    if (unlikely(nm_perm > 0)) return 0;
    return orig_generic_permission(PERM_CALL);
}

static permission_t orig_inode_permission;
static int hook_inode_permission(PERM_ARGS) {
    int nm_perm = nomount_handle_permission(inode, mask);
    if (unlikely(nm_perm < 0)) return nm_perm;
    if (unlikely(nm_perm > 0)) return 0;
    return orig_inode_permission(PERM_CALL);
}

/* --- 3. getname Hook --- */
static void nomount_handle_getname(struct filename *name)
{
    struct nomount_rule *rule;
    const char *check_name, *p, *s, *last_slash, *page_buf = NULL;
    size_t name_len, b_len, r_len;
    bool basename_match = false;
    u32 b_hash;
    char fast_buf[512]; 

    if (unlikely(__nomount_should_skip() || IS_ERR_OR_NULL(name) || !name->name))
        return;

    s = name->name; p = s;
    while (*p) { if (*p == '/') last_slash = p; p++; }

    name_len = (size_t)(p - s);
    if (unlikely(name_len <= 1)) return;

    check_name = (last_slash && *(last_slash + 1) != '\0') ? last_slash + 1 : s;
    if (likely(!(READ_ONCE(nm_basename_filter) & (1ULL << (check_name[0] & 63))))) return;

    b_len = name_len - (check_name - s);
    b_hash = full_name_hash(NULL, check_name, b_len);

    rcu_read_lock();
    if (unlikely(s[0] == '/' && !list_empty(&nomount_private_dirs_list) && current_uid().val >= AID_APP_START)) {
        struct nomount_dir_node *priv_dir;
        list_for_each_entry_rcu(priv_dir, &nomount_private_dirs_list, private_list) {
            size_t len = priv_dir->dir.len;
            if (name_len >= len && s[1] == priv_dir->dir_path[1] && memcmp(s, priv_dir->dir_path, len) == 0) {
                if (unlikely(s[len] == '\0' || s[len] == '/')) {
                    rcu_read_unlock();
                    return;
                }
            }
        }
    }

    hash_for_each_possible_rcu(nomount_basenames_ht, rule, basename_node, b_hash) {
        if (rule->b_len == b_len && memcmp(rule->basename, check_name, b_len) == 0) {
            basename_match = true;
            break;
        }
    }
    rcu_read_unlock();
    if (unlikely(!basename_match)) return;

    check_name = s;
    r_len = name_len;
    if (unlikely(s[0] != '/')) {
        page_buf = nomount_build_path_from_pwd(s, name_len, &r_len, &check_name, fast_buf);
        if (!page_buf) return;
    }

    rcu_read_lock();
    rule = nomount_get_rule_by_path(check_name, r_len);
    if (likely(rule)) {
        nm_debug("Redirected: %s -> %s\n", check_name, rule->real_path);
        memcpy((char *)name->name, rule->real_path, rule->real_node.len);
        ((char *)name->name)[rule->real_node.len] = '\0';
    }
    rcu_read_unlock();

    if (page_buf && page_buf != fast_buf) 
        __putname(page_buf);
}

typedef struct filename *(*getname_flags_t)(const char __user *, int, int *);
static getname_flags_t orig_getname_flags;

static struct filename *hook_getname_flags(const char __user *filename, int flags, int *empty) {
    struct filename *name = orig_getname_flags(filename, flags, empty);
    if (likely(!__nomount_should_skip() && !IS_ERR(name) && name->name)) {
        nomount_handle_getname(name);
    }
    return name;
}

typedef struct filename *(*getname_kernel_t)(const char *);
static getname_kernel_t orig_getname_kernel;

static struct filename *hook_getname_kernel(const char *filename) {
    struct filename *name = orig_getname_kernel(filename);
    if (likely(!__nomount_should_skip() && !IS_ERR(name) && name->name)) {
        nomount_handle_getname(name);
    }
    return name;
}

/* --- 4. Open and Lookup Hooks --- */
struct open_flags;
typedef struct file *(*do_filp_open_t)(int dfd, struct filename *pathname, const struct open_flags *op);
static do_filp_open_t orig_do_filp_open;

static struct file *hook_do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op) {
    if (likely(!__nomount_should_skip() && !IS_ERR_OR_NULL(pathname) && pathname->name)) {
        nomount_handle_getname(pathname);
    }
    return orig_do_filp_open(dfd, pathname, op);
}

typedef int (*filename_lookup_t)(int dfd, struct filename *name, unsigned flags, struct path *path, struct path *root);
static filename_lookup_t orig_filename_lookup;

static int hook_filename_lookup(int dfd, struct filename *name, unsigned flags, struct path *path, struct path *root) {
    if (likely(!__nomount_should_skip() && !IS_ERR_OR_NULL(name) && name->name)) {
        nomount_handle_getname(name);
    }
    return orig_filename_lookup(dfd, name, flags, path, root);
}

/* --- 5. iterate_dir Hook --- */
typedef int (*iterate_dir_t)(struct file *, struct dir_context *);
static iterate_dir_t orig_iterate_dir;

static int hook_iterate_dir(struct file *file, struct dir_context *ctx) {
    loff_t real_pos = file->f_pos; 
    loff_t nomount_magic_pos = 0x7000000000000000ULL;
    struct nm_inode_node *inode_node;
    struct nomount_dir_node *curr_dir;
    struct nm_child_array *array = NULL;
    struct inode *dir_inode;
    unsigned long v_index;
    u32 i;

    if (ctx->pos < nomount_magic_pos || !static_branch_unlikely(&nomount_active_dirs) || __nomount_should_skip())
        return orig_iterate_dir(file, ctx);

#ifdef CONFIG_COMPAT
    if (in_compat_syscall()) nomount_magic_pos = 0x7E000000;
#endif

    dir_inode = d_backing_inode(file->f_path.dentry);
    if (!dir_inode) return orig_iterate_dir(file, ctx);

    rcu_read_lock();
    hash_for_each_possible_rcu(nomount_inodes_ht, inode_node, node, dir_inode->i_ino) {
        if (likely(inode_node->ino == dir_inode->i_ino && inode_node->dev == dir_inode->i_sb->s_dev)) {
            if (likely(inode_node->type & NM_INO_TYPE_DIR)) {
                curr_dir = container_of(inode_node, struct nomount_dir_node, dir);
                array = rcu_dereference(curr_dir->child_array);
                if (likely(array && atomic_inc_not_zero(&array->refcnt))) break;
                array = NULL;
            }
            break;
        }
    }
    rcu_read_unlock();
    if (!array) return orig_iterate_dir(file, ctx);

    if (real_pos >= nomount_magic_pos) {
        v_index = (unsigned long)(real_pos - nomount_magic_pos);
    } else {
        v_index = 0;
        ctx->pos = nomount_magic_pos;
    }

    for (i = v_index; i < array->num_children; i++) {
        struct nomount_child_name *child = &array->entries[i];
        unsigned char type = child->d_type ? child->d_type : DT_REG;
        if (!dir_emit(ctx, child->name, child->name_len, child->fake_ino, type))
            break;
        ctx->pos = nomount_magic_pos + i + 1;
    }

    file->f_pos = ctx->pos;
    if (atomic_dec_and_test(&array->refcnt)) kfree_rcu(array, rcu);

    return 0;
}

/* --- 6. vfs_getattr Hook --- */
typedef int (*vfs_getattr_t)(const struct path *, struct kstat *, u32, unsigned int);
static vfs_getattr_t orig_vfs_getattr;

static int hook_vfs_getattr(const struct path *path, struct kstat *stat, u32 request_mask, unsigned int query_flags) {
    struct nm_inode_node *inode_node;
    struct nomount_rule *rule;
    struct inode *inode;

    if (unlikely(__nomount_should_skip() || IS_ERR_OR_NULL(path) || IS_ERR_OR_NULL(stat))) 
        return orig_vfs_getattr(path, stat, request_mask, query_flags);

    inode = d_backing_inode(path->dentry);
    if (unlikely(IS_ERR_OR_NULL(inode) || IS_ERR_OR_NULL(inode->i_sb)))
        return orig_vfs_getattr(path, stat, request_mask, query_flags);

    rcu_read_lock();
    hash_for_each_possible_rcu(nomount_inodes_ht, inode_node, node, inode->i_ino) {
        if (inode_node->ino == inode->i_ino && inode_node->dev == inode->i_sb->s_dev) {
            if (inode_node->type & NM_INO_TYPE_REAL) {
                rule = container_of(inode_node, struct nomount_rule, real_node);
                stat->ino = READ_ONCE(rule->virt_node.ino);
                if (rule->virt_node.dev != 0)
                    stat->dev = READ_ONCE(rule->virt_node.dev);
            }
            break;
        }
    }
    rcu_read_unlock();
    return orig_vfs_getattr(path, stat, request_mask, query_flags);
}

/* --- 7. vfs_statfs Hook --- */
typedef int (*vfs_statfs_t)(const struct path *path, struct kstatfs *buf);
static vfs_statfs_t orig_vfs_statfs;

static int hook_vfs_statfs(const struct path *path, struct kstatfs *buf) {
    struct nm_inode_node *inode_node;
    struct nomount_rule *rule = NULL;
    struct inode *inode;

    if (__nomount_should_skip() || IS_ERR_OR_NULL(path) || IS_ERR_OR_NULL(buf))
        return orig_vfs_statfs(path, buf);

    inode = d_backing_inode(path->dentry);
    if (unlikely(IS_ERR_OR_NULL(inode) || IS_ERR_OR_NULL(inode->i_sb))) return orig_vfs_statfs(path, buf);

    rcu_read_lock();
    hash_for_each_possible_rcu(nomount_inodes_ht, inode_node, node, inode->i_ino) {
        if (inode_node->ino == inode->i_ino && inode_node->dev == inode->i_sb->s_dev) {
            switch (inode_node->type) {
                case NM_INO_TYPE_REAL:
                    rule = container_of(inode_node, struct nomount_rule, real_node);
                    break;
                case NM_INO_TYPE_VIRTUAL:
                    rule = container_of(inode_node, struct nomount_rule, virt_node);
                    break;
                default:
                    goto unlock; 
            }
            if (rule && rule->v_fs_type != 0) 
                buf->f_type = READ_ONCE(rule->v_fs_type);
            break;
        }
    }

unlock:
    rcu_read_unlock();
    return orig_vfs_statfs(path, buf);
}

/* --- 8. sys_reboot Hook --- */
#if defined(__x86_64__)
    #define SYS_REBOOT_NAME "__x64_sys_reboot"
#elif defined(__aarch64__)
    #define SYS_REBOOT_NAME "__arm64_sys_reboot"
#else
    #define SYS_REBOOT_NAME "sys_reboot"
#endif

typedef long (*sys_reboot_t)(const struct pt_regs *regs);
static sys_reboot_t orig_sys_reboot;
static long nm_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg);

static long hook_sys_reboot(const struct pt_regs *regs) {
    int magic1, magic2;
    unsigned int cmd;
    void __user *arg;
    long ret;

#if defined(__x86_64__)
    magic1 = (int)regs->di;
    magic2 = (int)regs->si;
    cmd    = (unsigned int)regs->dx;
    arg    = (void __user *)regs->r10;
#elif defined(__aarch64__)
    magic1 = (int)regs->regs[0];
    magic2 = (int)regs->regs[1];
    cmd    = (unsigned int)regs->regs[2];
    arg    = (void __user *)regs->regs[3];
#else
    return orig_sys_reboot(regs); 
#endif

    ret = nm_handle_sys_reboot(magic1, magic2, cmd, arg);
    if (unlikely(ret == -ENOSYS)) {
        return orig_sys_reboot(regs);
    }

    return ret;
}

/* Hook Definitions Array */

static struct nm_hook hooks[] = {
    { .name = "d_path",             .hook_fn = hook_d_path,             .orig_fn = &orig_d_path },
    { .name = "generic_permission", .hook_fn = hook_generic_permission, .orig_fn = &orig_generic_permission },
    { .name = "inode_permission",   .hook_fn = hook_inode_permission,   .orig_fn = &orig_inode_permission },
    { .name = "getname_flags",      .hook_fn = hook_getname_flags,      .orig_fn = &orig_getname_flags },
    { .name = "getname_kernel",     .hook_fn = hook_getname_kernel,     .orig_fn = &orig_getname_kernel },
    { .name = "do_filp_open",       .hook_fn = hook_do_filp_open,       .orig_fn = &orig_do_filp_open },
    { .name = "filename_lookup",    .hook_fn = hook_filename_lookup,    .orig_fn = &orig_filename_lookup },
    { .name = "iterate_dir",        .hook_fn = hook_iterate_dir,        .orig_fn = &orig_iterate_dir },
    { .name = "vfs_getattr",        .hook_fn = hook_vfs_getattr,        .orig_fn = &orig_vfs_getattr },
    { .name = "vfs_statfs",         .hook_fn = hook_vfs_statfs,         .orig_fn = &orig_vfs_statfs },
    { .name = SYS_REBOOT_NAME,      .hook_fn = hook_sys_reboot,         .orig_fn = &orig_sys_reboot },
};

/*** Module Management ***/

/**
 * __nomount_get_or_create_dir - Factory function to retrieve or create a directory node
 * @ino: Inode number of the directory
 * @dev: Device ID of the directory
 *
 * Checks if a directory node already exists for the given inode. If not, allocates
 * a new node from nm_dir_cachep, initializes its lists, and adds it to the global
 * hash table.
 *
 * Return a pointer to the nomount_dir_node on success, NULL on failure (ENOMEM).
 */
static inline struct nomount_dir_node* __nomount_get_or_create_dir(unsigned long ino, dev_t dev)
{
    struct nm_inode_node *inode_node;
    struct nomount_dir_node *dir_node;

    hash_for_each_possible(nomount_inodes_ht, inode_node, node, ino) {
        if (inode_node->ino == ino && inode_node->dev == dev) {
            if (likely(inode_node->type & NM_INO_TYPE_DIR)) {
                return container_of(inode_node, struct nomount_dir_node, dir);
            }
        }
    }

    dir_node = kmem_cache_alloc(nm_dir_cachep, GFP_KERNEL);
    if (unlikely(!dir_node)) return NULL;

    dir_node->dir.ino = ino;
    dir_node->dir.dev = dev;
    dir_node->dir.len = 0;
    dir_node->dir.type = NM_INO_TYPE_DIR;
    dir_node->dir_path = NULL;
    dir_node->is_private = false;
    INIT_LIST_HEAD(&dir_node->private_list);
    RCU_INIT_POINTER(dir_node->child_array, NULL);
    hash_add_rcu(nomount_inodes_ht, &dir_node->dir.node, ino);
    atomic_inc(&nm_active_dirs);
    if (atomic_read(&nm_active_dirs) == 1) static_branch_enable(&nomount_active_dirs);

    return dir_node;
}

/* __nomount_collect_parents - Walks the dentry tree to register directory hierarchy
 * @rule: The rule containing the absolute real_path string
 * @d: A valid referenced dentry resolved from kern_path
 *
 * This function recursively climbs the dentry tree starting from the provided 
 * dentry. It registers every parent inode encountered and handles the extraction 
 * of private directory paths automatically when traversal permissions are restricted.
 *
 * This function relies on the caller to provide a valid reference (dget).
 */
static void __nomount_collect_parents(struct nomount_rule *rule, struct dentry *d)
{
    struct dentry *parent;
    char *r_tmp = rule->real_path, *slash, *slashes[32];
    int p_count = 0;

    while (d && !IS_ROOT(d) && p_count < 32) {
        struct inode *inode = d_backing_inode(d);
        if (likely(inode && S_ISDIR(inode->i_mode))) {
            struct nomount_dir_node *dir_node = __nomount_get_or_create_dir(inode->i_ino, inode->i_sb->s_dev);
            if (likely(dir_node)) {
                rule->parent_dir = dir_node;
                if (unlikely(!(inode->i_mode & S_IXOTH) && !dir_node->dir_path)) {
                    dir_node->is_private = true;
                    nm_debug("Registered private dir: %s (ino: %lu)\n", r_tmp, inode->i_ino);
                    dir_node->dir.len = strlen(r_tmp);
                    dir_node->dir_path = kmemdup_nul(r_tmp, dir_node->dir.len, GFP_KERNEL);
                    if (likely(dir_node->dir_path)) {
                        list_add_tail_rcu(&dir_node->private_list, &nomount_private_dirs_list);
                    }
                }
            }
        }

        slash = strrchr(r_tmp, '/');
        if (!slash || slash == r_tmp) break;
        *slash = '\0';
        slashes[p_count++] = slash;

        parent = dget_parent(d);
        dput(d);
        d = parent;
    }

    if (d) dput(d);
    while (p_count > 0) *slashes[--p_count] = '/';
}

/**
 * __nomount_inject_child_locked - Atomically inserts a virtual child into a parent
 * @dir_node: The parent directory node to inject into
 * @rule: The rule associated with the child being injected (used for metadata inheritance)
 * @name: Filename of the child
 * @name_len: Length of the name string
 * @name_hash: Precalculated hash of the name string
 * @type: File type (DT_DIR, DT_REG, etc.)
 * @child_fake_ino: The synthetic inode number for the virtual file
 *
 * This function performs an hash check to see if the child already exists 
 * to prevent duplicates, then appends it to the directory's child array.
 *
 * NOTE: Caller MUST hold the mutex lock to prevent concurrent writers, 
 * but RCU readers can continue without blocking.
 */
static void __nomount_inject_child_locked(struct nomount_dir_node *dir_node, struct nomount_rule *rule,
                                          const char *name, size_t name_len, u32 name_hash,
                                          unsigned char type, unsigned long child_fake_ino)
{
    struct nm_child_array *old_array, *new_array;
    u32 i, old_num = 0;

    if (unlikely(!dir_node)) return;
    rule->parent_dir = dir_node;

    old_array = rcu_dereference_protected(dir_node->child_array, lockdep_is_held(&nomount_write_mutex));
    if (old_array) {
        old_num = old_array->num_children;
        for (i = 0; i < old_num; i++) {
            if (old_array->entries[i].name_len == name_len &&
                !memcmp(old_array->entries[i].name, name, name_len)) {
                return;
            }
        }
    }

    new_array = kmalloc(sizeof(struct nm_child_array) + (old_num + 1) * sizeof(struct nomount_child_name), GFP_KERNEL);
    if (unlikely(!new_array)) return;

    atomic_set(&new_array->refcnt, 1);
    new_array->num_children = old_num + 1;

    if (old_array) memcpy(new_array->entries, old_array->entries, 
                          old_num * sizeof(struct nomount_child_name));

    memcpy(new_array->entries[old_num].name, name, name_len + 1);
    new_array->entries[old_num].name_len = (u16)name_len;
    new_array->entries[old_num].d_type = type;
    new_array->entries[old_num].fake_ino = child_fake_ino;
    rcu_assign_pointer(dir_node->child_array, new_array);

    if (old_array && atomic_dec_and_test(&old_array->refcnt)) {
        kfree_rcu(old_array, rcu);
    }
}

static void __nomount_delete_child_locked(struct nomount_dir_node *dir_node, unsigned long fake_ino, 
                                          struct hlist_head *d_victims)
{
    struct nm_child_array *old_array, *new_array;
    int found_idx = -1;
    u32 i, num, dst = 0;

    old_array = rcu_dereference_protected(dir_node->child_array, lockdep_is_held(&nomount_write_mutex));
    if (!old_array) return;

    num = old_array->num_children;
    for (i = 0; i < num; i++) {
        if (old_array->entries[i].fake_ino == fake_ino) {
            found_idx = i;
            break;
        }
    }
    if (found_idx == -1) return;

    if (num == 1) {
        rcu_assign_pointer(dir_node->child_array, NULL);
        if (atomic_dec_and_test(&old_array->refcnt)) kfree_rcu(old_array, rcu);
        hash_del_rcu(&dir_node->dir.node);
        if (unlikely(dir_node->is_private)) list_del_rcu(&dir_node->private_list);
        atomic_dec(&nm_active_dirs);
        if (atomic_read(&nm_active_dirs) == 0) static_branch_disable(&nomount_active_dirs);
        hlist_add_head(&dir_node->dir.node, d_victims);
    } else {
        new_array = kmalloc(sizeof(struct nm_child_array) + (num - 1) * sizeof(struct nomount_child_name), GFP_KERNEL);
        if (unlikely(!new_array)) return;

        atomic_set(&new_array->refcnt, 1);
        new_array->num_children = num - 1;
        for (i = 0; i < num; i++) {
            if (i == found_idx) continue;
            memcpy(&new_array->entries[dst++], &old_array->entries[i], sizeof(struct nomount_child_name));
        }
        rcu_assign_pointer(dir_node->child_array, new_array);
        if (atomic_dec_and_test(&old_array->refcnt))
            kfree_rcu(old_array, rcu);
    }
}

/**
 * nomount_generate_virtual_topology - Autogenerates intermediate directory rules
 * @rule: The main rule being added
 *
 * Walks the path backwards using in-place mutation to find the closest
 * native parent, inherits its metadata (s_dev, s_magic), and auto-injects
 * intermediate virtual directory rules to satisfy VFS lookups.
 *
 * Returns 0 on success, or negative error code (e.g., -ENOMEM) on failure.
 */
static int nomount_generate_virtual_topology(struct nomount_rule *rule)
{
    struct nomount_rule *ex, *irule = NULL, *t_rule, *pending_rules[32];
    struct path p_path, r_path_struct;
    char *v_tmp = rule->virtual_path, *r_tmp = rule->real_path;
    char *slash_v, *slash_r, *b_slash, *slashes_v[32], *slashes_r[32];
    int cur_v_len = rule->virt_node.len, cur_r_len = rule->real_node.len;
    int p_count = 0, err = 0, current_flags = rule->flags;
    unsigned long inherited_dev = 0, inherited_fs_type = 0;
    unsigned long current_parent_ino; dev_t current_parent_dev;
    const char *b_name_inter, *child_name;
    bool inter_exists;
    size_t child_name_len;
    u32 child_name_hash, h_inter;

    while (p_count < 32) {
        slash_v = strrchr(v_tmp, '/');
        slash_r = r_tmp ? strrchr(r_tmp, '/') : NULL; 
        if (slash_r == r_tmp) slash_r = NULL;
        if (!slash_v || slash_v == v_tmp) {
            if (likely(kern_path("/", LOOKUP_FOLLOW, &p_path) == 0)) {
                current_parent_ino = d_backing_inode(p_path.dentry)->i_ino;
                current_parent_dev = d_backing_inode(p_path.dentry)->i_sb->s_dev;
                child_name = v_tmp + 1;
                child_name_len = strlen(child_name);
                child_name_hash = full_name_hash(NULL, child_name, child_name_len);
                t_rule = (p_count == 0) ? rule : pending_rules[p_count - 1];
                __nomount_inject_child_locked(__nomount_get_or_create_dir(current_parent_ino, current_parent_dev),
                                              t_rule, child_name, child_name_len, child_name_hash,
                                              (current_flags & NM_FLAG_IS_DIR) ? DT_DIR : DT_REG, t_rule->v_hash);
                path_put(&p_path);
            }
            break;
        }

        *slash_v = '\0';
        slashes_v[p_count] = slash_v;
        cur_v_len = slash_v - v_tmp;

        if (slash_r) {
            *slash_r = '\0';
            slashes_r[p_count] = slash_r;
            cur_r_len = slash_r - r_tmp;
        } else {
            slashes_r[p_count] = NULL;
        }

        pending_rules[p_count] = NULL; 
        p_count++;
        h_inter = full_name_hash(NULL, v_tmp, cur_v_len);
        inter_exists = false;

        hash_for_each_possible(nomount_rules_ht, ex, vpath_node, h_inter) {
            if (ex->virt_node.len == cur_v_len && memcmp(ex->virtual_path, v_tmp, cur_v_len) == 0) {
                inherited_dev = ex->virt_node.dev;
                inherited_fs_type = ex->v_fs_type;
                current_parent_ino = ex->virt_node.ino;
                current_parent_dev = ex->virt_node.dev;
                inter_exists = true;
                break;
            }
        }

        if (inter_exists) {
            child_name = slash_v + 1;
            child_name_len = strlen(child_name);
            child_name_hash = full_name_hash(NULL, child_name, child_name_len);
            t_rule = (p_count == 1) ? rule : pending_rules[p_count - 2];
            __nomount_inject_child_locked(__nomount_get_or_create_dir(current_parent_ino, current_parent_dev),
                                          t_rule, child_name, child_name_len, child_name_hash,
                                          (current_flags & NM_FLAG_IS_DIR) ? DT_DIR : DT_REG, t_rule->v_hash);
            break;
        }

        if (likely(kern_path(v_tmp, LOOKUP_FOLLOW, &p_path) == 0)) {
            inherited_dev = p_path.dentry->d_sb->s_dev;
            if (p_path.dentry->d_sb->s_op->statfs) {
                struct kstatfs st;
                p_path.dentry->d_sb->s_op->statfs(p_path.dentry, &st);
                inherited_fs_type = st.f_type;
            } else {
                inherited_fs_type = p_path.dentry->d_sb->s_magic;
            }
            current_parent_ino = d_backing_inode(p_path.dentry)->i_ino;
            current_parent_dev = d_backing_inode(p_path.dentry)->i_sb->s_dev;
            child_name = slash_v + 1;
            child_name_len = strlen(child_name);
            child_name_hash = full_name_hash(NULL, child_name, child_name_len);
            t_rule = (p_count == 1) ? rule : pending_rules[p_count - 2];
            __nomount_inject_child_locked(__nomount_get_or_create_dir(current_parent_ino, current_parent_dev),
                                          t_rule, child_name, child_name_len, child_name_hash,
                                          (current_flags & NM_FLAG_IS_DIR) ? DT_DIR : DT_REG, t_rule->v_hash);
            path_put(&p_path);
            break; 
        } else {
            pending_rules[p_count - 1] = kmem_cache_alloc(nm_rule_cachep, GFP_KERNEL);
            if (unlikely(!pending_rules[p_count - 1])) {
                err = -ENOMEM;
                break;
            }

            irule = pending_rules[p_count - 1];

            INIT_LIST_HEAD(&irule->list);
            INIT_HLIST_NODE(&irule->vpath_node);
            INIT_HLIST_NODE(&irule->basename_node);

            irule->virtual_path = kmemdup_nul(v_tmp, cur_v_len, GFP_KERNEL);
            irule->real_path = slash_r ? kmemdup_nul(r_tmp, cur_r_len, GFP_KERNEL) : kstrdup("/", GFP_KERNEL);
            if (unlikely(!irule->virtual_path || !irule->real_path)) {
                if (irule->virtual_path) kfree(irule->virtual_path);
                if (irule->real_path) kfree(irule->real_path);
                kmem_cache_free(nm_rule_cachep, irule);
                pending_rules[p_count - 1] = NULL;
                err = -ENOMEM;
                break;
            }

            b_slash = strrchr(irule->virtual_path, '/');
            b_name_inter = b_slash ? b_slash + 1 : irule->virtual_path;
            irule->basename = b_name_inter;
            irule->b_len = (u16)strlen(b_name_inter);
            irule->v_hash = h_inter;
            irule->flags = NM_FLAG_IS_DIR;

            irule->virt_node.dev = 0;
            irule->virt_node.ino = (unsigned long)h_inter;
            irule->virt_node.len = (u16)cur_v_len;
            irule->virt_node.type = NM_INO_TYPE_VIRTUAL;
            irule->real_node.ino = 0;
            irule->real_node.dev = 0;
            irule->real_node.len = (u16)(slash_r ? cur_r_len : 1);
            irule->real_node.type = NM_INO_TYPE_REAL;

            if (slash_r) {
                if (likely(kern_path(irule->real_path, LOOKUP_FOLLOW, &r_path_struct) == 0)) {
                    irule->real_node.ino = d_backing_inode(r_path_struct.dentry)->i_ino;
                    irule->real_node.dev = r_path_struct.dentry->d_sb->s_dev;
                    path_put(&r_path_struct);
                }
            }
        }
        current_flags = NM_FLAG_IS_DIR;
    }

    while (p_count > 0) {
        p_count--;
        if (slashes_v[p_count]) *slashes_v[p_count] = '/';
        if (slashes_r[p_count]) *slashes_r[p_count] = '/';

        if (pending_rules[p_count]) {
            irule = pending_rules[p_count];

            if (likely(err == 0)) {
                u32 bh = full_name_hash(NULL, irule->basename, irule->b_len);
                irule->virt_node.dev = inherited_dev;
                irule->v_fs_type = inherited_fs_type;

                hash_add_rcu(nomount_basenames_ht, &irule->basename_node, bh);
                hash_add_rcu(nomount_rules_ht, &irule->vpath_node, irule->v_hash);
                if (irule->real_node.ino) hash_add_rcu(nomount_inodes_ht, &irule->real_node.node, irule->real_node.ino);
                hash_add_rcu(nomount_inodes_ht, &irule->virt_node.node, irule->virt_node.ino);
                
                list_add_tail_rcu(&irule->list, &nomount_rules_list);
                atomic_inc(&nm_active_rules);
                if (atomic_read(&nm_active_rules) == 1) static_branch_enable(&nomount_active_rules);
            } else {
                kfree(irule->virtual_path);
                kfree(irule->real_path);
                kmem_cache_free(nm_rule_cachep, irule);
            }
        }
    }

    if (likely(err == 0)) {
        rule->virt_node.dev = inherited_dev;
        rule->v_fs_type = inherited_fs_type;
    }

    return err;
}

/*** Rule Operations ***/

static int __nomount_add_rule(const char *v_path, const char *r_path, u16 v_len, u16 r_len, u32 flags)
{
    struct nomount_rule *rule, *existing, *victim = NULL;
    struct path path_main, r_path_struct_main;
    struct dentry *r_path_dentry = NULL;
    char *slash;
    const char *b_name;
    u32 hash, b_hash;
    int err = 0;
    bool v_path_exists = false; 

    if (!v_path || !r_path) return -EINVAL;

    hash = full_name_hash(NULL, v_path, v_len);
    rule = kmem_cache_alloc(nm_rule_cachep, GFP_KERNEL);
    if (!rule)
        return -ENOMEM;

    rule->virtual_path = kmemdup_nul(v_path, v_len, GFP_KERNEL);
    rule->real_path = kmemdup_nul(r_path, r_len, GFP_KERNEL);

    if (!rule->virtual_path || !rule->real_path) {
        if (rule->virtual_path) kfree(rule->virtual_path);
        if (rule->real_path) kfree(rule->real_path);
        kmem_cache_free(nm_rule_cachep, rule);
        return -ENOMEM;
    }

    INIT_LIST_HEAD(&rule->list);
    INIT_HLIST_NODE(&rule->vpath_node);
    INIT_HLIST_NODE(&rule->basename_node);

    slash = strrchr(rule->virtual_path, '/');
    b_name = slash ? slash + 1 : rule->virtual_path;
    rule->basename = b_name;
    rule->b_len = strlen(b_name);
    rule->v_hash = hash;
    rule->flags = flags;

    rule->real_node.ino = 0;
    rule->real_node.dev = 0;
    rule->real_node.len = r_len;
    rule->real_node.type = NM_INO_TYPE_REAL;
    rule->virt_node.ino = 0;
    rule->virt_node.dev = 0;
    rule->virt_node.len = v_len;
    rule->virt_node.type = NM_INO_TYPE_VIRTUAL;

    if (kern_path(rule->real_path, LOOKUP_FOLLOW, &r_path_struct_main) == 0) {
        struct inode *r_inode = d_backing_inode(r_path_struct_main.dentry);
        rule->real_node.ino = r_inode->i_ino;
        rule->real_node.dev = r_path_struct_main.dentry->d_sb->s_dev;
        if (S_ISDIR(r_inode->i_mode)) rule->flags |= NM_FLAG_IS_DIR;
        r_path_dentry = dget(r_path_struct_main.dentry);
        path_put(&r_path_struct_main);
    }

    if (kern_path(rule->virtual_path, LOOKUP_FOLLOW, &path_main) == 0) {
        rule->virt_node.ino = d_backing_inode(path_main.dentry)->i_ino;
        rule->virt_node.dev = path_main.dentry->d_sb->s_dev;
        if (path_main.dentry->d_sb->s_op->statfs) {
            struct kstatfs st;
            path_main.dentry->d_sb->s_op->statfs(path_main.dentry, &st);
            rule->v_fs_type = st.f_type;
        } else {
            rule->v_fs_type = path_main.dentry->d_sb->s_magic;
        }
        path_put(&path_main);
        v_path_exists = true;
        nm_debug("Resolved physical backing for %s (ino: %lu)\n", rule->virtual_path, rule->virt_node.ino);
    } else {
        rule->virt_node.ino = (unsigned long)hash;
    }

    mutex_lock(&nomount_write_mutex);
    hash_for_each_possible(nomount_rules_ht, existing, vpath_node, hash) {
        if (existing->v_hash == hash && existing->virt_node.len == v_len &&
             memcmp(existing->virtual_path, rule->virtual_path, v_len) == 0) {
            hash_del_rcu(&existing->vpath_node);
            hash_del_rcu(&existing->basename_node);
            if (existing->real_node.ino) hash_del_rcu(&existing->real_node.node);
            if (existing->virt_node.ino) hash_del_rcu(&existing->virt_node.node);
            list_del_rcu(&existing->list);
            atomic_dec(&nm_active_rules);
            victim = existing;
            nm_info("Shadowing existing rule for: %s\n", rule->virtual_path);
            break;
        }
    }

    if (!v_path_exists) {
        err = nomount_generate_virtual_topology(rule);
        if (err != 0) {
            mutex_unlock(&nomount_write_mutex);
            if (r_path_dentry) dput(r_path_dentry);
            kfree(rule->virtual_path);
            kfree(rule->real_path);
            kmem_cache_free(nm_rule_cachep, rule);
            return err;
        }
    }
    
    if (r_path_dentry)
        __nomount_collect_parents(rule, r_path_dentry);

    b_hash = full_name_hash(NULL, rule->basename, rule->b_len);
    hash_add_rcu(nomount_basenames_ht, &rule->basename_node, b_hash);
    hash_add_rcu(nomount_rules_ht, &rule->vpath_node, hash);

    if (rule->real_node.ino)
        hash_add_rcu(nomount_inodes_ht, &rule->real_node.node, rule->real_node.ino);

    if (rule->virt_node.ino)
        hash_add_rcu(nomount_inodes_ht, &rule->virt_node.node, rule->virt_node.ino);

    list_add_tail_rcu(&rule->list, &nomount_rules_list);
    atomic_inc(&nm_active_rules);
    if (atomic_read(&nm_active_rules) == 1) static_branch_enable(&nomount_active_rules);

    if (likely(rule->basename && rule->b_len > 0))
        nm_basename_filter |= (1ULL << (rule->basename[0] & 63));

    mutex_unlock(&nomount_write_mutex);

    if (unlikely(victim)) {
        synchronize_rcu();
        kfree(victim->virtual_path);
        kfree(victim->real_path);
        kmem_cache_free(nm_rule_cachep, victim);
    }

    nm_info("Successfully added rule: %s -> %s\n", rule->virtual_path, rule->real_path);
    return 0;
}

static void __nomount_del_rule(const char *v_path, size_t v_len,
                               struct list_head *r_victims,
                               struct hlist_head *d_victims)
{
    struct nomount_rule *rule;
    u32 hash = full_name_hash(NULL, v_path, v_len);

    hash_for_each_possible(nomount_rules_ht, rule, vpath_node, hash) {
        if (rule->v_hash == hash && rule->virt_node.len == v_len &&
             memcmp(rule->virtual_path, v_path, v_len) == 0) {
            hash_del_rcu(&rule->vpath_node);
            hash_del_rcu(&rule->basename_node);
            if (rule->real_node.ino) hash_del_rcu(&rule->real_node.node);
            if (rule->virt_node.ino) hash_del_rcu(&rule->virt_node.node);
            list_del_rcu(&rule->list);
            atomic_dec(&nm_active_rules);
            if (atomic_read(&nm_active_rules) == 0) static_branch_disable(&nomount_active_rules);
            list_add_tail(&rule->list, r_victims);
            if (rule->parent_dir)
                __nomount_delete_child_locked(rule->parent_dir, hash, d_victims);

            __nomount_rebuild_basename_filter();
            break;
        }
    }
}

static void __nomount_clear_all(void)
{
    struct nomount_rule *rule, *tmp_rule;
    struct nomount_dir_node *dir_node, *tmp_dir;
    struct nomount_uid_node *uid_node;
    struct nm_inode_node *inode_node;
    struct hlist_node *hlist_tmp;
    struct nm_child_array *array;
    LIST_HEAD(rule_victims);
    LIST_HEAD(dir_victims);
    HLIST_HEAD(uid_victims);
    int bkt;

    list_for_each_entry_safe(rule, tmp_rule, &nomount_rules_list, list) {
        hash_del_rcu(&rule->vpath_node);
        hash_del_rcu(&rule->basename_node);
        if (rule->real_node.ino) hash_del_rcu(&rule->real_node.node);
        if (rule->virt_node.ino) hash_del_rcu(&rule->virt_node.node);
        list_move_tail(&rule->list, &rule_victims);
    }

    hash_for_each_safe(nomount_uid_ht, bkt, hlist_tmp, uid_node, node) {
        hash_del_rcu(&uid_node->node);
        hlist_add_head(&uid_node->node, &uid_victims);
    }

    hash_for_each_safe(nomount_inodes_ht, bkt, hlist_tmp, inode_node, node) {
        if (inode_node->type & NM_INO_TYPE_DIR) {
            dir_node = container_of(inode_node, struct nomount_dir_node, dir);
            hash_del_rcu(&inode_node->node);
            array = rcu_dereference_protected(dir_node->child_array, 1);
            if (array) kfree_rcu(array, rcu);
            if (dir_node->is_private) list_del_rcu(&dir_node->private_list);
            list_add_tail(&dir_node->private_list, &dir_victims);
        }
    }

    atomic_set(&nm_active_rules, 0);
    atomic_set(&nm_active_dirs, 0);
    atomic_set(&nm_active_uids, 0);
    static_branch_disable(&nomount_active_rules);
    static_branch_disable(&nomount_active_dirs);
    static_branch_disable(&nomount_active_uids);
    WRITE_ONCE(nm_basename_filter, 0);
    INIT_LIST_HEAD(&nomount_private_dirs_list);
    synchronize_rcu();

    list_for_each_entry_safe(dir_node, tmp_dir, &dir_victims, private_list) {
        kfree(dir_node->dir_path);
        kmem_cache_free(nm_dir_cachep, dir_node);
    }
    list_for_each_entry_safe(rule, tmp_rule, &rule_victims, list) {
        kfree(rule->virtual_path);
        kfree(rule->real_path);
        kmem_cache_free(nm_rule_cachep, rule);
    }
    hlist_for_each_entry_safe(uid_node, hlist_tmp, &uid_victims, node) {
        kmem_cache_free(nm_uid_cachep, uid_node);
    }
}

static long nm_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg) 
{
    struct nomount_reboot_payload *payload = NULL;
    long ret = -EINVAL;

    if (magic1 != NOMOUNT_MAGIC1 || magic2 != NOMOUNT_MAGIC2) {
        return -ENOSYS;
    }

    if (cmd == NOMOUNT_CMD_CLEAR_ALL) {
        mutex_lock(&nomount_write_mutex);
        __nomount_clear_all();
        mutex_unlock(&nomount_write_mutex);
        nm_info("Cleared all rules via stealth reboot IPC\n");
        return 0;
    }
    if (cmd == NOMOUNT_CMD_GET_VERSION) {
        return NOMOUNT_VERSION;
    }

    if (!arg) return -EINVAL;
    payload = kmalloc(sizeof(*payload), GFP_KERNEL);
    if (!payload) return -ENOMEM;

    if (_copy_from_user(payload, arg, sizeof(*payload))) {
        kfree(payload);
        return -EFAULT;
    }

    switch (cmd) {
        case NOMOUNT_CMD_ADD_RULE:
            payload->virtual_path[PATH_MAX - 1] = '\0';
            payload->real_path[PATH_MAX - 1] = '\0';
            ret = __nomount_add_rule(payload->virtual_path, payload->real_path, 
                                     strlen(payload->virtual_path), strlen(payload->real_path), 
                                     payload->flags);
            break;

        case NOMOUNT_CMD_DEL_RULE: {
            LIST_HEAD(r_victims);
            HLIST_HEAD(d_victims);
            struct nomount_rule *rule, *tmp_r;
            struct nomount_dir_node *dir;
            struct hlist_node *tmp_d;
            struct nm_inode_node *inode_node;

            payload->virtual_path[PATH_MAX - 1] = '\0';

            mutex_lock(&nomount_write_mutex);
            __nomount_del_rule(payload->virtual_path, strlen(payload->virtual_path), &r_victims, &d_victims);
            mutex_unlock(&nomount_write_mutex);

            if (list_empty(&r_victims)) {
                ret = -ENOENT;
                break;
            }
            
            synchronize_rcu();

            hlist_for_each_entry_safe(inode_node, tmp_d, &d_victims, node) {
                dir = container_of(inode_node, struct nomount_dir_node, dir);
                kfree(dir->dir_path);
                kmem_cache_free(nm_dir_cachep, dir);
            }

            list_for_each_entry_safe(rule, tmp_r, &r_victims, list) {
                nm_info("Deleted rule for: %s via stealth reboot\n", rule->virtual_path);
                kfree(rule->virtual_path);
                kfree(rule->real_path);
                kmem_cache_free(nm_rule_cachep, rule);
            }
            ret = 0;
            break;
        }

        case NOMOUNT_CMD_GET_LIST: {
            struct nomount_rule *rule;
            u32 current_idx = 0;
            u32 target_idx = payload->flags; 
            bool found = false;

            rcu_read_lock();
            list_for_each_entry_rcu(rule, &nomount_rules_list, list) {
                if (current_idx == target_idx) {
                    strncpy(payload->virtual_path, rule->virtual_path, PATH_MAX - 1);
                    strncpy(payload->real_path, rule->real_path, PATH_MAX - 1);
                    payload->flags = rule->flags;
                    found = true;
                    break;
                }
                current_idx++;
            }
            rcu_read_unlock();
            if (!found) { ret = -ENOENT; break; }

            if (_copy_to_user(arg, payload, sizeof(*payload))) {
                ret = -EFAULT;
            } else {
                ret = 0;
            }
            break;
        }

        case NOMOUNT_CMD_ADD_UID: {
            struct nomount_uid_node *entry;
            if (nomount_is_uid_blocked(payload->uid)) {
                ret = -EEXIST;
                break;
            }

            entry = kmem_cache_alloc(nm_uid_cachep, GFP_KERNEL);
            if (!entry) {
                ret = -ENOMEM;
                break;
            }
            entry->uid = payload->uid;

            mutex_lock(&nomount_write_mutex);
            hash_add_rcu(nomount_uid_ht, &entry->node, payload->uid);
            atomic_inc(&nm_active_uids);
            if (atomic_read(&nm_active_uids) == 1) static_branch_enable(&nomount_active_uids);
            mutex_unlock(&nomount_write_mutex);

            nm_info("Successfully added blocked UID: %u via stealth reboot\n", payload->uid);
            ret = 0;
            break;
        }

        case NOMOUNT_CMD_DEL_UID: {
            struct nomount_uid_node *entry;
            struct hlist_node *tmp;
            int bkt;
            bool found = false;

            mutex_lock(&nomount_write_mutex);
            hash_for_each_safe(nomount_uid_ht, bkt, tmp, entry, node) {
                if (entry->uid == payload->uid) {
                    hash_del_rcu(&entry->node);
                    found = true; break; 
                }
            }
            if (found) {
                atomic_dec(&nm_active_uids);
                if (atomic_read(&nm_active_uids) == 0) static_branch_disable(&nomount_active_uids);
            }
            mutex_unlock(&nomount_write_mutex);

            if (found && entry) {
                synchronize_rcu();
                kmem_cache_free(nm_uid_cachep, entry);
            }

            nm_info("Successfully removed blocked UID: %u via stealth reboot\n", payload->uid);
            ret = found ? 0 : -ENOENT;
            break;
        }

        default:
            ret = -EINVAL;
            break;
    }

    kfree(payload);
    return ret;
}

static int __init nomount_init(void) {
    int ret, i;

    /* Initialize hash tables */
    hash_init(nomount_rules_ht);
    hash_init(nomount_basenames_ht);
    hash_init(nomount_uid_ht);
    hash_init(nomount_inodes_ht);

    nm_rule_cachep = kmem_cache_create("nm_rules", sizeof(struct nomount_rule), 0, SLAB_HWCACHE_ALIGN, NULL);
    nm_dir_cachep = kmem_cache_create("nm_dirs", sizeof(struct nomount_dir_node), 0, SLAB_HWCACHE_ALIGN, NULL);
    nm_uid_cachep = kmem_cache_create("nm_uids", sizeof(struct nomount_uid_node), 0, SLAB_HWCACHE_ALIGN, NULL);

    if (!nm_rule_cachep || !nm_dir_cachep || !nm_uid_cachep) {
        nm_err("Failed to allocate memory slab caches\n");
        if (nm_rule_cachep) kmem_cache_destroy(nm_rule_cachep);
        if (nm_dir_cachep) kmem_cache_destroy(nm_dir_cachep);
        if (nm_uid_cachep) kmem_cache_destroy(nm_uid_cachep);
        return -ENOMEM;
    }

    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        ret = nm_install_hook(&hooks[i]);
        if (ret) {
            nm_err("Failed to install hook: %s\n", hooks[i].name);
            while (i != 0) nm_remove_hook(&hooks[--i]);
            synchronize_rcu();
            kmem_cache_destroy(nm_rule_cachep);
            kmem_cache_destroy(nm_dir_cachep);
            kmem_cache_destroy(nm_uid_cachep);
            return ret;
        } else { 
            nm_info("Hook successfully installed: %s\n", hooks[i].name);
        }
    }

    nm_info("Loaded successfully\n");
    return 0;
}

static void __exit nomount_exit(void) {
    int i;

    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        nm_remove_hook(&hooks[i]);
    }

    synchronize_rcu();

    mutex_lock(&nomount_write_mutex);
    __nomount_clear_all();
    mutex_unlock(&nomount_write_mutex);

    kmem_cache_destroy(nm_rule_cachep);
    kmem_cache_destroy(nm_dir_cachep);
    kmem_cache_destroy(nm_uid_cachep);

    nm_info("Unloaded successfully\n");
}

MODULE_LICENSE("GPL");
MODULE_VERSION("10");
MODULE_AUTHOR("maxsteeel");
MODULE_DESCRIPTION("NoMount Path Redirection VFS Subsystem");

module_init(nomount_init);
module_exit(nomount_exit);
