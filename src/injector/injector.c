#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>

#define MMAP_SIZE   0x10000
#define __NR_mmap   9
#define __NR_munmap 11

// =========================================================================
// Common utilities
// =========================================================================

typedef struct {
    char **items;
    size_t len;
    size_t cap;
} StrVec;

static void vec_push(StrVec *vec, char *value) {
    if (vec->len + 1 >= vec->cap) {
        size_t next = vec->cap == 0 ? 16 : vec->cap * 2;
        char **items = realloc(vec->items, next * sizeof(*items));
        if (!items) { fprintf(stderr, "[-] Out of memory\n"); exit(1); }
        vec->items = items;
        vec->cap = next;
    }
    vec->items[vec->len++] = value;
    vec->items[vec->len] = NULL;
}

static char *xstrdup(const char *s) {
    char *copy = strdup(s);
    if (!copy) { fprintf(stderr, "[-] Out of memory\n"); exit(1); }
    return copy;
}

static bool starts_with(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

// =========================================================================
// Ptrace injection helpers
// =========================================================================

static uint64_t GetModuleInfo(pid_t pid, const char *module_name,
                              char *path_out, size_t path_len) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *f = fopen(maps_path, "r");
    if (!f) return 0;

    char line[512];
    uint64_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, module_name)) {
            uint64_t start, end, file_offset;
            char perms[5];
            if (sscanf(line, "%lx-%lx %4s %lx", &start, &end, perms, &file_offset) >= 4)
                base = start - file_offset;

            if (path_out) {
                char *p = line;
                int field = 0;
                while (*p && field < 5) {
                    while (*p && *p != ' ') p++;
                    while (*p == ' ') p++;
                    field++;
                }
                if (*p) {
                    char *nl = strchr(p, '\n');
                    if (nl) *nl = '\0';
                    while (*p == ' ') p++;
                    strncpy(path_out, p, path_len - 1);
                    path_out[path_len - 1] = '\0';
                }
            }
            break;
        }
    }
    fclose(f);
    return base;
}

static uint64_t GetSymbolOffset(const char *lib_path, const char *sym_name) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "nm -D '%s' 2>/dev/null | grep -E ' [TtWw] %s(@@|$)' | head -1",
        lib_path, sym_name);

    FILE *p = popen(cmd, "r");
    if (!p) return 0;

    uint64_t offset = 0;
    char line[256];
    if (fgets(line, sizeof(line), p))
        sscanf(line, "%lx", &offset);

    pclose(p);
    return offset;
}

static int PtraceRead(pid_t pid, uint64_t addr, void *buf, size_t len) {
    size_t i = 0;
    while (i < len) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i), NULL);
        if (errno != 0) return -1;
        size_t chunk = (len - i < sizeof(long)) ? (len - i) : sizeof(long);
        memcpy((char *)buf + i, &word, chunk);
        i += sizeof(long);
    }
    return 0;
}

static int PtraceWrite(pid_t pid, uint64_t addr, const void *buf, size_t len) {
    size_t i = 0;
    while (i < len) {
        long word;
        if (len - i < sizeof(long)) {
            errno = 0;
            word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i), NULL);
            if (errno != 0) return -1;
            memcpy(&word, (const char *)buf + i, len - i);
        } else {
            memcpy(&word, (const char *)buf + i, sizeof(long));
        }
        if (ptrace(PTRACE_POKEDATA, pid, (void *)(addr + i), (void *)word) != 0)
            return -1;
        i += sizeof(long);
    }
    return 0;
}

static int64_t RemoteSyscall(pid_t pid, struct user_regs_struct *saved_regs,
                             long nr, long a1, long a2, long a3,
                             long a4, long a5, long a6) {
    uint64_t orig_code;
    if (PtraceRead(pid, saved_regs->rip, &orig_code, 8) != 0) {
        fprintf(stderr, "[-] RemoteSyscall: cannot read code at RIP\n");
        return -1;
    }

    uint64_t patched = (orig_code & ~0xFFFFUL) | 0x050FUL;
    PtraceWrite(pid, saved_regs->rip, &patched, 8);

    struct user_regs_struct regs;
    memcpy(&regs, saved_regs, sizeof(regs));
    regs.rax      = nr;
    regs.rdi      = a1;
    regs.rsi      = a2;
    regs.rdx      = a3;
    regs.r10      = a4;
    regs.r8       = a5;
    regs.r9       = a6;
    regs.orig_rax = -1;
    regs.rip      = saved_regs->rip;

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);

    int status;
    waitpid(pid, &status, 0);

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    int64_t result = (int64_t)regs.rax;

    PtraceWrite(pid, saved_regs->rip, &orig_code, 8);
    ptrace(PTRACE_SETREGS, pid, NULL, saved_regs);

    return result;
}

static int WaitForTrap(pid_t pid) {
    for (int i = 0; i < 30; i++) {
        int status;
        waitpid(pid, &status, 0);
        if (!WIFSTOPPED(status)) {
            fprintf(stderr, "[-] Target exited unexpectedly\n");
            return -1;
        }
        int sig = WSTOPSIG(status);
        if (sig == SIGTRAP)
            return 0;
        if (sig == SIGSEGV || sig == SIGBUS || sig == SIGABRT || sig == SIGFPE) {
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            fprintf(stderr, "[-] Crash! Signal=%d RIP=0x%llx RSP=0x%llx RAX=0x%llx\n",
                sig, (unsigned long long)regs.rip,
                (unsigned long long)regs.rsp,
                (unsigned long long)regs.rax);
            return -1;
        }
        ptrace(PTRACE_CONT, pid, NULL, NULL);
    }
    fprintf(stderr, "[-] Timed out waiting for SIGTRAP\n");
    return -1;
}

// =========================================================================
// Mode 1: Ptrace injection into a running process
// =========================================================================

static int do_ptrace_inject(pid_t target_pid, const char *so_path) {
    printf("[*] Target PID: %d\n", target_pid);
    printf("[*] Library:    %s\n", so_path);

    char remote_libc_path[512] = {0};
    uint64_t remote_base = GetModuleInfo(target_pid, "libc.so",
                                         remote_libc_path, sizeof(remote_libc_path));
    if (remote_base == 0 || remote_libc_path[0] == '\0') {
        fprintf(stderr, "[-] Cannot find libc in target process\n");
        return 1;
    }

    char real_libc_path[600];
    snprintf(real_libc_path, sizeof(real_libc_path),
             "/proc/%d/root%s", target_pid, remote_libc_path);
    if (access(real_libc_path, R_OK) != 0) {
        strncpy(real_libc_path, remote_libc_path, sizeof(real_libc_path) - 1);
        real_libc_path[sizeof(real_libc_path) - 1] = '\0';
    }

    printf("[*] Target libc: %s (base=0x%lx)\n", remote_libc_path, remote_base);
    printf("[*] Host path:   %s\n", real_libc_path);

    uint64_t dlopen_offset = GetSymbolOffset(real_libc_path, "dlopen");
    const char *sym_used = "dlopen";
    if (dlopen_offset == 0) {
        dlopen_offset = GetSymbolOffset(real_libc_path, "__libc_dlopen_mode");
        sym_used = "__libc_dlopen_mode";
    }
    if (dlopen_offset == 0) {
        fprintf(stderr, "[-] Cannot find dlopen in %s\n", real_libc_path);
        fprintf(stderr, "    Try: nm -D %s | grep dlopen\n", real_libc_path);
        return 1;
    }

    uint64_t remote_dlopen = remote_base + dlopen_offset;
    printf("[*] %s: offset=0x%lx -> remote=0x%lx\n", sym_used, dlopen_offset, remote_dlopen);

    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) != 0) {
        fprintf(stderr, "[-] PTRACE_ATTACH failed: %s\n", strerror(errno));
        return 1;
    }

    int status;
    waitpid(target_pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "[-] Target did not stop\n");
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 1;
    }
    printf("[+] Attached\n");

    struct user_regs_struct old_regs;
    if (ptrace(PTRACE_GETREGS, target_pid, NULL, &old_regs) != 0) {
        fprintf(stderr, "[-] PTRACE_GETREGS failed\n");
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 1;
    }

    int64_t mmap_ret = RemoteSyscall(target_pid, &old_regs,
        __NR_mmap, 0, MMAP_SIZE,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (mmap_ret <= 0 || mmap_ret == (int64_t)-1) {
        fprintf(stderr, "[-] Remote mmap failed (0x%lx)\n", (uint64_t)mmap_ret);
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 1;
    }

    uint64_t mem = (uint64_t)mmap_ret;
    printf("[+] Remote mmap: 0x%lx\n", mem);

    uint64_t path_addr = mem;
    uint64_t code_addr = mem + 0x1000;
    uint64_t stack_top = (mem + MMAP_SIZE - 0x100) & ~0xFUL;

    size_t path_len = strlen(so_path) + 1;
    PtraceWrite(target_pid, path_addr, so_path, path_len);

    uint8_t shellcode[] = {
        0x48, 0xB8, 0,0,0,0,0,0,0,0,        // mov rax, imm64
        0xFF, 0xD0,                          // call rax
        0xCC                                 // int3
    };
    memcpy(&shellcode[2], &remote_dlopen, 8);

    PtraceWrite(target_pid, code_addr, shellcode, sizeof(shellcode));

    uint8_t verify[sizeof(shellcode)];
    PtraceRead(target_pid, code_addr, verify, sizeof(verify));
    printf("[*] Shellcode at 0x%lx: ", code_addr);
    for (size_t i = 0; i < sizeof(verify); i++) printf("%02x ", verify[i]);
    printf("\n");

    struct user_regs_struct exec_regs;
    memcpy(&exec_regs, &old_regs, sizeof(exec_regs));
    exec_regs.rip      = code_addr;
    exec_regs.rdi      = path_addr;
    exec_regs.rsi      = RTLD_NOW;
    exec_regs.rsp      = stack_top;
    exec_regs.rbp      = 0;
    exec_regs.orig_rax = -1;

    ptrace(PTRACE_SETREGS, target_pid, NULL, &exec_regs);

    printf("[*] Executing %s...\n", sym_used);
    ptrace(PTRACE_CONT, target_pid, NULL, NULL);

    int ok = WaitForTrap(target_pid);

    if (ok == 0) {
        struct user_regs_struct result_regs;
        ptrace(PTRACE_GETREGS, target_pid, NULL, &result_regs);
        uint64_t handle = result_regs.rax;

        if (handle != 0)
            printf("[+] Success! Handle: 0x%lx\n", handle);
        else
            fprintf(stderr, "[-] dlopen returned NULL. Check: ldd %s\n", so_path);
    }

    ptrace(PTRACE_SETREGS, target_pid, NULL, &old_regs);
    RemoteSyscall(target_pid, &old_regs,
        __NR_munmap, mem, MMAP_SIZE, 0, 0, 0, 0);
    ptrace(PTRACE_SETREGS, target_pid, NULL, &old_regs);
    ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
    printf("[+] Detached\n");

    return (ok == 0) ? 0 : 1;
}

// =========================================================================
// Mode 2: Flatpak LD_PRELOAD injection (launch-time)
// =========================================================================

static char *dirname_dup(const char *path) {
    char *copy = xstrdup(path);
    char *slash = strrchr(copy, '/');
    if (!slash) { free(copy); return xstrdup("."); }
    if (slash == copy) slash[1] = '\0';
    else *slash = '\0';
    return copy;
}

static void print_command(char *const argv[]) {
    for (size_t i = 0; argv[i]; i++) {
        if (i > 0) putchar(' ');
        putchar('\'');
        for (const char *p = argv[i]; *p; p++) {
            if (*p == '\'') fputs("'\\''", stdout);
            else putchar(*p);
        }
        putchar('\'');
    }
    putchar('\n');
}

static int do_flatpak_inject(const char *app_id, const char *so_path,
                             bool dry_run,
                             StrVec *extra_filesystems, StrVec *extra_envs,
                             int app_argc, char **app_argv) {
    struct stat st;
    if (stat(so_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "[-] SO_PATH is not a regular file: %s\n", so_path);
        return 1;
    }
    if (access(so_path, R_OK) != 0) {
        fprintf(stderr, "[-] SO_PATH is not readable: %s\n", so_path);
        return 1;
    }

    char *so_dir = dirname_dup(so_path);
    char *fs_arg = NULL;
    char *preload_arg = NULL;
    if (asprintf(&fs_arg, "--filesystem=%s:ro", so_dir) < 0 ||
        asprintf(&preload_arg, "--env=LD_PRELOAD=%s", so_path) < 0) {
        fprintf(stderr, "[-] Out of memory\n");
        return 1;
    }

    StrVec cmd = {0};
    vec_push(&cmd, xstrdup("flatpak"));
    vec_push(&cmd, xstrdup("run"));
    vec_push(&cmd, fs_arg);
    vec_push(&cmd, preload_arg);

    for (size_t i = 0; i < extra_filesystems->len; i++)
        vec_push(&cmd, extra_filesystems->items[i]);
    for (size_t i = 0; i < extra_envs->len; i++)
        vec_push(&cmd, extra_envs->items[i]);

    vec_push(&cmd, xstrdup(app_id));
    for (int i = 0; i < app_argc; i++)
        vec_push(&cmd, app_argv[i]);

    if (dry_run) {
        print_command(cmd.items);
        return 0;
    }

    printf("[*] Launching: flatpak run %s\n", app_id);
    printf("[*] LD_PRELOAD=%s\n", so_path);

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "[-] fork failed: %s\n", strerror(errno));
        return 1;
    }
    if (pid == 0) {
        setsid();
        execvp("flatpak", cmd.items);
        fprintf(stderr, "[-] Failed to exec flatpak: %s\n", strerror(errno));
        _exit(1);
    }

    printf("[+] Started in background (pid %d)\n", pid);
    return 0;
}

// =========================================================================
// Usage & main
// =========================================================================

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s -p <pid> <path_to_so>\n"
        "      Inject .so into a running process via ptrace.\n"
        "      Requires root or CAP_SYS_PTRACE.\n"
        "\n"
        "  %s -f <app_id> -s <path_to_so> [options] [-- app_args...]\n"
        "      Launch a Flatpak app with .so injected via LD_PRELOAD.\n"
        "\n"
        "Flatpak options:\n"
        "  -n, --dry-run              Print the flatpak command without running it\n"
        "      --filesystem=SPEC      Extra flatpak filesystem permission\n"
        "      --env=KEY=VALUE        Extra environment passed to flatpak\n"
        "\n"
        "Examples:\n"
        "  sudo %s -p 12345 ./librevokehook.so\n"
        "  %s -f com.tencent.WeChat -s ./librevokehook.so\n"
        "  %s -f com.tencent.WeChat -s ./librevokehook.so -n\n",
        prog, prog, prog, prog, prog);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    // Ptrace mode: -p <pid> <so_path>
    if (strcmp(argv[1], "-p") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s -p <pid> <path_to_so>\n", argv[0]);
            return 1;
        }
        pid_t pid = (pid_t)atoi(argv[2]);
        const char *so_path = argv[3];

        char abs_path[PATH_MAX];
        if (realpath(so_path, abs_path) == NULL) {
            fprintf(stderr, "[-] Cannot resolve path: %s (%s)\n", so_path, strerror(errno));
            return 1;
        }
        if (access(abs_path, R_OK) != 0) {
            fprintf(stderr, "[-] Cannot access: %s\n", abs_path);
            return 1;
        }

        return do_ptrace_inject(pid, abs_path);
    }

    // Flatpak mode: -f <app_id> -s <so_path> [options...]
    if (strcmp(argv[1], "-f") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s -f <app_id> -s <path_to_so> [options]\n", argv[0]);
            return 1;
        }

        const char *app_id = argv[2];
        const char *so_arg = NULL;
        bool dry_run = false;
        StrVec extra_filesystems = {0};
        StrVec extra_envs = {0};

        int i = 3;
        int app_argc = 0;
        char **app_argv = NULL;

        for (; i < argc; i++) {
            const char *arg = argv[i];
            if (strcmp(arg, "--") == 0) { i++; break; }
            if (strcmp(arg, "-s") == 0 || strcmp(arg, "--so") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "[-] Missing value for -s\n");
                    return 1;
                }
                so_arg = argv[++i];
            } else if (starts_with(arg, "--so=")) {
                so_arg = arg + 5;
            } else if (strcmp(arg, "-n") == 0 || strcmp(arg, "--dry-run") == 0) {
                dry_run = true;
            } else if (starts_with(arg, "--filesystem=")) {
                vec_push(&extra_filesystems, xstrdup(arg));
            } else if (starts_with(arg, "--env=")) {
                if (!strchr(arg + 6, '=')) {
                    fprintf(stderr, "[-] --env must be KEY=VALUE\n");
                    return 1;
                }
                vec_push(&extra_envs, xstrdup(arg));
            } else if (arg[0] == '-') {
                fprintf(stderr, "[-] Unknown option: %s\n", arg);
                return 1;
            } else {
                break;
            }
        }

        if (!so_arg) {
            fprintf(stderr, "[-] Missing -s <path_to_so>\n");
            return 1;
        }

        app_argc = argc - i;
        app_argv = argv + i;

        char abs_path[PATH_MAX];
        if (realpath(so_arg, abs_path) == NULL) {
            fprintf(stderr, "[-] Cannot resolve SO path: %s (%s)\n", so_arg, strerror(errno));
            return 1;
        }

        return do_flatpak_inject(app_id, abs_path, dry_run,
                                 &extra_filesystems, &extra_envs,
                                 app_argc, app_argv);
    }

    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        usage(argv[0]);
        return 0;
    }

    fprintf(stderr, "[-] Unknown mode. Use -p (ptrace) or -f (flatpak).\n");
    usage(argv[0]);
    return 1;
}
