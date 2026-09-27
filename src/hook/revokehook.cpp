#define _GNU_SOURCE
#include "sigbp.h"

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <cerrno>
#include <string>
#include <vector>
#include <chrono>
#include <random>
#include <map>

#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>

#include <openssl/md5.h>

// -----------------------------------------------------------------------
// Breakpoint addresses
// -----------------------------------------------------------------------

static void *g_bpDelMsg = nullptr;
static void *g_bpAdd2DB = nullptr;

// -----------------------------------------------------------------------
// Per-thread state (pthread TLS, replaces Windows TLS)
// -----------------------------------------------------------------------

static pthread_key_t g_tlsThreadState;
static int g_tlsThreadStateCreated = 0;

struct ThreadState {
    uint8_t last_org_srvid[8];
    uint8_t anti_revoke_cur_msg;
};

static void ThreadStateDestructor(void *ptr) {
    free(ptr);
}

static ThreadState *GetThreadState() {
    if (!g_tlsThreadStateCreated)
        return nullptr;

    auto *state = (ThreadState *)pthread_getspecific(g_tlsThreadState);
    if (state != nullptr)
        return state;

    state = (ThreadState *)calloc(1, sizeof(ThreadState));
    if (state == nullptr)
        return nullptr;

    if (pthread_setspecific(g_tlsThreadState, state) != 0) {
        free(state);
        return nullptr;
    }

    return state;
}

static bool InitThreadStateTls() {
    if (g_tlsThreadStateCreated)
        return true;
    if (pthread_key_create(&g_tlsThreadState, ThreadStateDestructor) != 0)
        return false;
    g_tlsThreadStateCreated = 1;
    return true;
}

static void UninitThreadStateTls() {
    if (!g_tlsThreadStateCreated)
        return;

    auto *state = (ThreadState *)pthread_getspecific(g_tlsThreadState);
    if (state) {
        free(state);
        pthread_setspecific(g_tlsThreadState, nullptr);
    }
    pthread_key_delete(g_tlsThreadState);
    g_tlsThreadStateCreated = 0;
}

// -----------------------------------------------------------------------
// Config structures (same layout as Windows version)
// -----------------------------------------------------------------------

struct BasicInfo {
    uint64_t imgbase;
    uint64_t add2db_offset;
    uint64_t delmsg_offset;
};

struct DelMsgInfo {
    bool initialized;
    int  arg_msg_index;
    int  offset_revoke_xml;
    int  arg_notify_index;
    int  string_layout;
};

struct Add2DBInfo {
    bool initialized;
    int  arg_msg_index;
    int  arg_bool_index;
    int  offset_srvid;
    int  offset_revoke_xml;
    int  string_layout;
};

struct ConfigInfo {
    BasicInfo  basic_info;
    DelMsgInfo delmsg_info;
    Add2DBInfo add2db_info;
} g_config_info;

enum ProgramStringLayout {
    PROGRAM_STRING_UNKNOWN  = 0,
    PROGRAM_STRING_SIZE_PTR = 1,
    PROGRAM_STRING_PTR_SIZE = 2,
};

// Normalized representation of either target layout:
//   [size, data pointer] or [data pointer, size]
struct ProgramString {
    uint64_t size;
    uint64_t data_addr;
};

static_assert(sizeof(ProgramString) == 16, "Unexpected ProgramString layout");

typedef std::map<std::string, std::map<std::string, std::string>> SimpleIni;

static SimpleIni g_ini;
static bool g_anti_revoke_self_msg = false;
static bool g_output_debug_msg    = false;
static bool g_search_delmsg_xml   = false;

// -----------------------------------------------------------------------
// Logging (writes to file since stderr is not visible in injected process)
// Default log path: ~/revokehook.log (persists after crash, visible outside sandbox)
// Override via env: REVOKEHOOK_LOG
// -----------------------------------------------------------------------

static int g_logfd = -1;
static char g_log_path[512] = {0};

static void LogInit() {
    if (g_logfd >= 0) return;

    const char *path = getenv("REVOKEHOOK_LOG");
    if (!path || !path[0]) {
        const char *cache_home = getenv("XDG_CACHE_HOME");
        if (cache_home && cache_home[0]) {
            snprintf(g_log_path, sizeof(g_log_path), "%s/revokehook.log", cache_home);
            path = g_log_path;
        } else {
            const char *home = getenv("HOME");
            if (home && home[0]) {
                snprintf(g_log_path, sizeof(g_log_path),
                         "%s/.cache/revokehook.log", home);
                path = g_log_path;
            } else {
                path = "/tmp/revokehook.log";
            }
        }
    }

    g_logfd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
}

static void LogClose() {
    if (g_logfd >= 0) {
        close(g_logfd);
        g_logfd = -1;
    }
}

static void LogPrintf(const char *fmt, ...) {
    if (g_logfd < 0) return;
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        if (n >= (int)sizeof(buf)) n = (int)sizeof(buf) - 1;
        write(g_logfd, buf, (size_t)n);
    }
}

static void DebugPrintf(const char *fmt, ...) {
    if (!g_output_debug_msg) return;
    if (g_logfd < 0) return;
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        if (n >= (int)sizeof(buf)) n = (int)sizeof(buf) - 1;
        buf[n] = '\n';
        write(g_logfd, buf, (size_t)n + 1);
    }
}

// -----------------------------------------------------------------------
// Safe access to target-process memory.
//
// The hook runs inside the target process, but addresses found while scanning
// are still untrusted. Reading them through /proc/self/mem makes invalid
// addresses fail with EIO/EFAULT instead of crashing on direct dereference.
// -----------------------------------------------------------------------

static int g_mem_fd = -1;

static bool ReadMemory(const void *addr, void *buffer, size_t size) {
    if (addr == nullptr || buffer == nullptr || size == 0 || g_mem_fd < 0)
        return false;

    size_t done = 0;
    while (done < size) {
        ssize_t n = pread(g_mem_fd, (uint8_t *)buffer + done, size - done,
                          (off_t)((uintptr_t)addr + done));
        if (n > 0) {
            done += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        return false;
    }
    return true;
}

static bool WriteMemory(void *addr, const void *buffer, size_t size) {
    if (addr == nullptr || buffer == nullptr || size == 0 || g_mem_fd < 0)
        return false;

    size_t done = 0;
    while (done < size) {
        ssize_t n = pwrite(g_mem_fd, (const uint8_t *)buffer + done, size - done,
                           (off_t)((uintptr_t)addr + done));
        if (n > 0) {
            done += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        return false;
    }
    return true;
}

static bool IsMemoryReadable(const void *addr, size_t size) {
    uint8_t buffer[256];
    uintptr_t current = (uintptr_t)addr;

    if (addr == nullptr || size == 0)
        return false;

    while (size > 0) {
        size_t chunk = size < sizeof(buffer) ? size : sizeof(buffer);
        if (!ReadMemory((const void *)current, buffer, chunk))
            return false;
        current += chunk;
        size -= chunk;
    }
    return true;
}

// -----------------------------------------------------------------------
// MD5 (replaces WinCrypt)
// -----------------------------------------------------------------------

static std::vector<uint8_t> CalculateMD5(const std::vector<uint8_t> &data) {
    uint8_t digest[MD5_DIGEST_LENGTH];
    MD5(data.data(), data.size(), digest);
    return std::vector<uint8_t>(digest + 4, digest + 12);
}

static std::vector<uint8_t> GetUniquePositiveValue() {
    auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    uint8_t salt = (uint8_t)dis(gen);

    std::vector<uint8_t> input;
    for (int i = 0; i < 6; i++)
        input.push_back((uint8_t)((now >> (i * 8)) & 0xFF));
    input.push_back(salt);

    std::vector<uint8_t> result = CalculateMD5(input);
    if (result.size() != 8) return {};

    result.back() &= 0x7F;
    return result;
}

// -----------------------------------------------------------------------
// Find module base address (replaces GetModuleHandle)
// Parses /proc/self/maps for the first mapping of the given module name.
// -----------------------------------------------------------------------

static uint64_t FindModuleBase(const char *module_name) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    char line[512];
    uint64_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, module_name)) {
            sscanf(line, "%lx-", &base);
            break;
        }
    }
    fclose(f);
    return base;
}

// -----------------------------------------------------------------------
// Register access helpers
//
// System V AMD64 ABI:  RDI, RSI, RDX, RCX, R8, R9, stack...
// (Windows MSVC x64:   RCX, RDX, R8,  R9,  stack...)
// -----------------------------------------------------------------------

static uint64_t GetArgValue(ucontext_t *ctx, int index) {
    if (ctx == nullptr || index <= 0)
        return 0;

    switch (index) {
    case 1: return (uint64_t)ctx->uc_mcontext.gregs[REG_RDI];
    case 2: return (uint64_t)ctx->uc_mcontext.gregs[REG_RSI];
    case 3: return (uint64_t)ctx->uc_mcontext.gregs[REG_RDX];
    case 4: return (uint64_t)ctx->uc_mcontext.gregs[REG_RCX];
    case 5: return (uint64_t)ctx->uc_mcontext.gregs[REG_R8];
    case 6: return (uint64_t)ctx->uc_mcontext.gregs[REG_R9];
    default: {
        uint64_t value = 0;
        uintptr_t addr = (uintptr_t)ctx->uc_mcontext.gregs[REG_RSP] +
                         8 + (size_t)(index - 7) * sizeof(value);
        if (!ReadMemory((const void *)addr, &value, sizeof(value)))
            return 0;
        return value;
    }
    }
}

static int SetArgValue(ucontext_t *ctx, int index, uint64_t value) {
    if (ctx == nullptr || index <= 0)
        return 0;

    switch (index) {
    case 1: ctx->uc_mcontext.gregs[REG_RDI] = (greg_t)value; return 1;
    case 2: ctx->uc_mcontext.gregs[REG_RSI] = (greg_t)value; return 1;
    case 3: ctx->uc_mcontext.gregs[REG_RDX] = (greg_t)value; return 1;
    case 4: ctx->uc_mcontext.gregs[REG_RCX] = (greg_t)value; return 1;
    case 5: ctx->uc_mcontext.gregs[REG_R8]  = (greg_t)value; return 1;
    case 6: ctx->uc_mcontext.gregs[REG_R9]  = (greg_t)value; return 1;
    default: {
        uintptr_t addr = (uintptr_t)ctx->uc_mcontext.gregs[REG_RSP] +
                         8 + (size_t)(index - 7) * sizeof(value);
        return WriteMemory((void *)addr, &value, sizeof(value)) ? 1 : 0;
    }
    }
}

static const char *GetArgRegisterName(int index) {
    switch (index) {
    case 1: return "RDI";
    case 2: return "RSI";
    case 3: return "RDX";
    case 4: return "RCX";
    case 5: return "R8";
    case 6: return "R9";
    default: return "STACK";
    }
}

// -----------------------------------------------------------------------
// Target program string search helpers
// -----------------------------------------------------------------------

static uint64_t FindSignatureInMemory(uint64_t data_addr, uint64_t data_size,
                                      const uint8_t *sig, size_t sig_len) {
    uint8_t buffer[4096];

    if (data_addr == 0 || sig == nullptr || sig_len == 0 ||
        sig_len > sizeof(buffer) || data_size < sig_len)
        return 0;

    uint64_t offset = 0;
    while (offset + sig_len <= data_size) {
        size_t chunk = (size_t)(data_size - offset);
        if (chunk > sizeof(buffer))
            chunk = sizeof(buffer);

        if (!ReadMemory((const void *)(uintptr_t)(data_addr + offset),
                        buffer, chunk))
            return 0;

        for (size_t i = 0; i + sig_len <= chunk; i++) {
            if (memcmp(buffer + i, sig, sig_len) == 0)
                return data_addr + offset + i;
        }

        if (chunk == data_size - offset)
            break;
        offset += chunk - (sig_len - 1);
    }
    return 0;
}

static bool ReadProgramString(uint64_t addr, int layout,
                              ProgramString *program_string) {
    uint64_t fields[2] = {};
    if (program_string == nullptr ||
        !ReadMemory((const void *)(uintptr_t)addr, fields, sizeof(fields)))
        return false;

    switch (layout) {
    case PROGRAM_STRING_SIZE_PTR:
        program_string->size = fields[0];
        program_string->data_addr = fields[1];
        return true;
    case PROGRAM_STRING_PTR_SIZE:
        program_string->data_addr = fields[0];
        program_string->size = fields[1];
        return true;
    default:
        return false;
    }
}

static bool FindProgramStringWithSig(uint64_t base_addr, size_t scan_range,
                                     const uint8_t *sig, size_t sig_len,
                                     uint64_t *found_addr,
                                     ProgramString *found_string,
                                     int *found_layout) {
    if (base_addr == 0 || found_addr == nullptr || found_string == nullptr ||
        found_layout == nullptr)
        return false;

    for (size_t offset = 0; offset + sizeof(ProgramString) <= scan_range; offset += 8) {
        uint64_t addr = base_addr + offset;
        uint64_t fields[2] = {};
        if (!ReadMemory((const void *)(uintptr_t)addr, fields, sizeof(fields)))
            break;

        const int layouts[] = {
            PROGRAM_STRING_SIZE_PTR,
            PROGRAM_STRING_PTR_SIZE,
        };

        for (int layout : layouts) {
            ProgramString str = {};
            if (layout == PROGRAM_STRING_SIZE_PTR) {
                str.size = fields[0];
                str.data_addr = fields[1];
            } else {
                str.data_addr = fields[0];
                str.size = fields[1];
            }

            if (str.size < sig_len || str.size > 0x10000 ||
                str.data_addr == 0)
                continue;

            if (FindSignatureInMemory(str.data_addr, str.size,
                                      sig, sig_len) == 0)
                continue;

            *found_addr = addr;
            *found_string = str;
            *found_layout = layout;
            return true;
        }
    }
    return false;
}

static int FindZeroArgIndex(ucontext_t *ctx, int start_idx, int end_idx) {
    for (int i = start_idx; i <= end_idx; i++) {
        if (GetArgValue(ctx, i) == 0)
            return i;
    }
    for (int i = start_idx; i <= end_idx; i++) {
        uint64_t val = GetArgValue(ctx, i);
        if (val != 0 && (val & 0xFFFFFFFF) == 0)
            return i;
    }
    for (int i = start_idx; i <= end_idx; i++) {
        uint64_t val = GetArgValue(ctx, i);
        if (val != 0 && (val & 0xFF) == 0 &&
            (val >= 0x10000 && val <= 0x00007FFFFFFFFFFF))
            return i;
    }
    return -1;
}

static uint64_t FindSrvId(uint64_t base_addr, size_t scan_limit) {
    for (size_t offset = 0; offset + 16 <= scan_limit; offset += 8) {
        uint8_t candidate[16];
        if (!ReadMemory((const void *)(uintptr_t)(base_addr + offset),
                        candidate, sizeof(candidate)))
            break;

        if (candidate[14] != 0x00 || candidate[15] != 0x00)
            continue;
        if (candidate[12] == 0x00 && candidate[13] == 0x00)
            continue;

        int non_zero_count = 0;
        for (int i = 0; i < 14; i++) {
            if (candidate[i] != 0) non_zero_count++;
        }
        if (non_zero_count == 14)
            return base_addr + offset;
    }
    return 0;
}

static bool SkipDirectCall(ucontext_t *ctx) {
    uint8_t instruction[5];
    uint64_t rip = (uint64_t)ctx->uc_mcontext.gregs[REG_RIP];

    if (!ReadMemory((const void *)(uintptr_t)rip,
                    instruction, sizeof(instruction)) ||
        instruction[0] != 0xE8) {
        DebugPrintf("[Debug] Refusing to skip non-E8 instruction at %p",
                    (void *)(uintptr_t)rip);
        return false;
    }

    ctx->uc_mcontext.gregs[REG_RIP] += sizeof(instruction);
    return true;
}

// -----------------------------------------------------------------------
// OnTargetHit — main hook callback (replaces Windows version)
// Called from SIGTRAP handler when a breakpoint fires.
// -----------------------------------------------------------------------

static void OnTargetHit(ucontext_t *ctx, siginfo_t * /*info*/) {
    uint64_t rip = (uint64_t)ctx->uc_mcontext.gregs[REG_RIP];
    ThreadState *ts = GetThreadState();
    if (ts == nullptr) {
        DebugPrintf("[RevokeHook] GetThreadState Failed!");
        return;
    }

    // ── Hook 1: DelMsg ──────────────────────────────────────────────────
    if (rip == (uint64_t)g_bpDelMsg) {
        if (!g_search_delmsg_xml) {
            ts->anti_revoke_cur_msg = 1;

            int arg_notify_index = FindZeroArgIndex(ctx, 3, 8);
            if (arg_notify_index > 0)
                SetArgValue(ctx, arg_notify_index, 1);

            DebugPrintf("[Debug] DelMsg: string search disabled, skip call");
            SkipDirectCall(ctx);
            return;
        }

        uint8_t revoke_sig[]      = { 0xe6, 0x92, 0xa4, 0xe5, 0x9b, 0x9e };           // '撤回'
        uint8_t self_revoke_sig[] = { 0xe4, 0xbd, 0xa0, 0xe6, 0x92, 0xa4, 0xe5, 0x9b, 0x9e }; // '你撤回'

        ProgramString revoke_xml = {};
        uint64_t revoke_xml_addr = 0;
        int revoke_xml_layout = PROGRAM_STRING_UNKNOWN;

        if (!g_config_info.delmsg_info.initialized) {
            // Dump registers for debugging
            DebugPrintf("[Debug] DelMsg hit! RDI=%lx RSI=%lx RDX=%lx RCX=%lx R8=%lx R9=%lx\n",
                (unsigned long)ctx->uc_mcontext.gregs[REG_RDI],
                (unsigned long)ctx->uc_mcontext.gregs[REG_RSI],
                (unsigned long)ctx->uc_mcontext.gregs[REG_RDX],
                (unsigned long)ctx->uc_mcontext.gregs[REG_RCX],
                (unsigned long)ctx->uc_mcontext.gregs[REG_R8],
                (unsigned long)ctx->uc_mcontext.gregs[REG_R9]);

            // System V ABI args 2,3,4 → RSI, RDX, RCX
            uint64_t candidates[] = {
                (uint64_t)ctx->uc_mcontext.gregs[REG_RSI],
                (uint64_t)ctx->uc_mcontext.gregs[REG_RDX],
                (uint64_t)ctx->uc_mcontext.gregs[REG_RCX]
            };
            int candidate_indices[] = { 2, 3, 4 };

            for (int c = 0; c < 3 && revoke_xml_addr == 0; c++) {
                if (FindProgramStringWithSig(candidates[c], 0x2000,
                                             revoke_sig, sizeof(revoke_sig),
                                             &revoke_xml_addr, &revoke_xml,
                                             &revoke_xml_layout)) {
                    g_config_info.delmsg_info.arg_msg_index = candidate_indices[c];
                    g_config_info.delmsg_info.offset_revoke_xml =
                        (int)(revoke_xml_addr - candidates[c]);
                    g_config_info.delmsg_info.string_layout = revoke_xml_layout;
                }
            }

            if (revoke_xml_addr == 0 || revoke_xml.size == 0) {
                DebugPrintf("[Debug] DelMsg: Cannot find revoke_xml, fallback to skip call");
                ts->anti_revoke_cur_msg = 1;

                int arg_notify_index = FindZeroArgIndex(ctx, 3, 8);
                if (arg_notify_index > 0)
                    SetArgValue(ctx, arg_notify_index, 1);

                SkipDirectCall(ctx);
                return;
            }

            g_config_info.delmsg_info.arg_notify_index = FindZeroArgIndex(ctx, 3, 8);
            g_config_info.delmsg_info.initialized = true;
            DebugPrintf("[Debug] DelMsg cached: msg_idx=%d, xml_off=0x%X, notify_idx=%d, layout=%d",
                g_config_info.delmsg_info.arg_msg_index,
                g_config_info.delmsg_info.offset_revoke_xml,
                g_config_info.delmsg_info.arg_notify_index,
                g_config_info.delmsg_info.string_layout);
        } else {
            uint64_t arg_msg = GetArgValue(ctx, g_config_info.delmsg_info.arg_msg_index);
            revoke_xml_addr = arg_msg + g_config_info.delmsg_info.offset_revoke_xml;
            if (!ReadProgramString(revoke_xml_addr,
                                   g_config_info.delmsg_info.string_layout,
                                   &revoke_xml) ||
                revoke_xml.size == 0) {
                DebugPrintf("[Debug] DelMsg: revoke_xml invalid (cached path)");
                return;
            }
        }

        uint64_t xml_addr = revoke_xml.data_addr;
        if (xml_addr == 0 || revoke_xml.size > 0x10000 ||
            !IsMemoryReadable((const void *)(uintptr_t)xml_addr,
                              (size_t)revoke_xml.size)) {
            DebugPrintf("[Debug] DelMsg: revoke_xml str invalid");
            return;
        }

        bool is_self = FindSignatureInMemory(
            xml_addr, revoke_xml.size,
            self_revoke_sig, sizeof(self_revoke_sig)) != 0;

        if (is_self && !g_anti_revoke_self_msg) {
            ts->anti_revoke_cur_msg = 0;
            return;
        }
        if (is_self)
            DebugPrintf("[Debug] Anti Revoke SELF Msg...");

        ts->anti_revoke_cur_msg = 1;

        if (g_config_info.delmsg_info.arg_notify_index > 0) {
            SetArgValue(ctx, g_config_info.delmsg_info.arg_notify_index, 1);
            DebugPrintf("[Debug] Set notify arg %d to 1",
                g_config_info.delmsg_info.arg_notify_index);
        }

        if (SkipDirectCall(ctx))
            DebugPrintf("[Debug] Skip Call, New RIP: %p",
                (void *)(uintptr_t)ctx->uc_mcontext.gregs[REG_RIP]);
    }

    // ── Hook 2: Add2DB ──────────────────────────────────────────────────
    else if (rip == (uint64_t)g_bpAdd2DB) {
        if (ts->anti_revoke_cur_msg == 0) return;

        if (!g_config_info.add2db_info.initialized) {
            const int arg_msg_index = 3;
            int arg_bool_index = FindZeroArgIndex(ctx, 3, 8);
            if (arg_bool_index < 0) {
                DebugPrintf("[Debug] Add2DB: Cannot find arg_bool (0 param)");
                return;
            }

            uint64_t arg_msg = GetArgValue(ctx, arg_msg_index);
            if (arg_msg == 0 || !IsMemoryReadable((void *)arg_msg, 0x100)) {
                DebugPrintf("[Debug] Add2DB: arg_msg is invalid");
                return;
            }

            uint8_t anchor[] = { 0xe4, 0xb8, 0x80, 0xe6, 0x9d, 0xa1 }; // '一条'
            ProgramString rx = {};
            uint64_t rx_addr = 0;
            int rx_layout = PROGRAM_STRING_UNKNOWN;
            if (!FindProgramStringWithSig(arg_msg, 0x1000,
                                          anchor, sizeof(anchor),
                                          &rx_addr, &rx, &rx_layout) ||
                rx.size == 0) {
                DebugPrintf("[Debug] Add2DB: Cannot find revoke_xml");
                return;
            }

            int xml_offset = (int)(rx_addr - arg_msg);
            uint64_t mem_srvid_addr = FindSrvId(arg_msg, (size_t)xml_offset);
            if (mem_srvid_addr == 0) {
                DebugPrintf("[Debug] Add2DB: Cannot find srvid");
                return;
            }

            g_config_info.add2db_info.arg_msg_index     = arg_msg_index;
            g_config_info.add2db_info.arg_bool_index    = arg_bool_index;
            g_config_info.add2db_info.offset_revoke_xml = xml_offset;
            g_config_info.add2db_info.offset_srvid      = (int)(mem_srvid_addr - arg_msg);
            g_config_info.add2db_info.string_layout      = rx_layout;
            g_config_info.add2db_info.initialized        = true;
            DebugPrintf("[Debug] Add2DB cached: msg_idx=%d(%s), bool_idx=%d, xml_off=0x%X, srvid_off=0x%X, layout=%d",
                g_config_info.add2db_info.arg_msg_index,
                GetArgRegisterName(g_config_info.add2db_info.arg_msg_index),
                g_config_info.add2db_info.arg_bool_index,
                g_config_info.add2db_info.offset_revoke_xml,
                g_config_info.add2db_info.offset_srvid,
                g_config_info.add2db_info.string_layout);
        }

        int      arg_bool_index = g_config_info.add2db_info.arg_bool_index;
        uint64_t arg_msg = GetArgValue(
            ctx, g_config_info.add2db_info.arg_msg_index);
        if (arg_msg == 0 || !IsMemoryReadable((void *)arg_msg, 0x100)) {
            DebugPrintf("[Debug] Add2DB: arg_msg invalid");
            return;
        }

        uint64_t revoke_xml_addr =
            arg_msg + g_config_info.add2db_info.offset_revoke_xml;
        ProgramString revoke_xml = {};
        if (!ReadProgramString(revoke_xml_addr,
                               g_config_info.add2db_info.string_layout,
                               &revoke_xml) ||
            revoke_xml.size == 0 || revoke_xml.size > 0x10000) {
            DebugPrintf("[Debug] Add2DB: revoke_xml invalid");
            return;
        }

        uint64_t mem_srvid_addr = arg_msg + g_config_info.add2db_info.offset_srvid;
        uint64_t xml_addr = revoke_xml.data_addr;
        if (xml_addr == 0 ||
            !IsMemoryReadable((const void *)(uintptr_t)xml_addr,
                              (size_t)revoke_xml.size)) {
            DebugPrintf("[Debug] Add2DB: revoke_xml data invalid");
            return;
        }
        DebugPrintf("[Debug] %p | Revoke XML addr=%p len=%lu | bool_idx: %d",
            (void *)(uintptr_t)revoke_xml_addr,
            (void *)(uintptr_t)xml_addr,
            (unsigned long)revoke_xml.size,
            arg_bool_index);

        // Deduplicate by srvid
        uint8_t org_srvid[8] = {};
        if (!ReadMemory((const void *)(uintptr_t)mem_srvid_addr,
                        org_srvid, sizeof(org_srvid))) {
            DebugPrintf("[Debug] Add2DB: Cannot read srvid");
            return;
        }
        if (memcmp(ts->last_org_srvid, org_srvid, 8) == 0)
            return;
        memcpy(ts->last_org_srvid, org_srvid, 8);

        // Generate unique SrvID via MD5
        std::vector<uint8_t> rand_srvid = GetUniquePositiveValue();
        if (rand_srvid.size() != 8) {
            DebugPrintf("[RevokeHook] GetUniquePositiveValue Err!");
            return;
        }
        DebugPrintf("[Debug] Original SrvID at %p: [%02X %02X...]",
            (void *)mem_srvid_addr,
            org_srvid[0], org_srvid[1]);
        if (!WriteMemory((void *)(uintptr_t)mem_srvid_addr,
                         rand_srvid.data(), rand_srvid.size())) {
            DebugPrintf("[Debug] Add2DB: Cannot replace srvid");
            return;
        }
        DebugPrintf("[Debug] New SrvID at %p: [%02X %02X %02X %02X...]",
            (void *)mem_srvid_addr,
            rand_srvid[0], rand_srvid[1], rand_srvid[2], rand_srvid[3]);

        // Replace '一条' → '如上'
        uint8_t anchor[]  = { 0xe4, 0xb8, 0x80, 0xe6, 0x9d, 0xa1 };
        uint8_t replace[] = { 0xe5, 0xa6, 0x82, 0xe4, 0xb8, 0x8a };
        uint64_t anchor_addr = FindSignatureInMemory(
            xml_addr, revoke_xml.size, anchor, sizeof(anchor));
        if (anchor_addr != 0 &&
            WriteMemory((void *)(uintptr_t)anchor_addr,
                        replace, sizeof(replace))) {
            DebugPrintf("[Debug] Replace Revoke XML Success!");
        }

        if (SetArgValue(ctx, arg_bool_index, 1))
            DebugPrintf("[Debug] Set Arg %d to 1", arg_bool_index);
        else
            DebugPrintf("[Debug] Set Arg %d Failed!", arg_bool_index);
    }
}

// -----------------------------------------------------------------------
// Config loading (replaces ReadExternalConfig)
//
// INI path priority:
//   1. REVOKEHOOK_INI environment variable
//   2. ~/.config/RevokeHook/RevokeHook.ini
//
// INI format:
//   [KeyFunc]
//   ModuleName   = <target .so name, e.g. "libwechat.so">
//   DelMsgOffset = <hex or decimal offset>
//   Add2DBOffset = <hex or decimal offset>
//
//   [Setting]
//   AntiRevokeSelf = false
//   OutputDebugMsg = false
// -----------------------------------------------------------------------

static std::string g_module_name;

static bool ReadConfig() {
    std::string ini_path;

    const char *env_path = getenv("REVOKEHOOK_INI");
    if (env_path && env_path[0]) {
        ini_path = env_path;
    } else {
        const char *home = getenv("HOME");
        if (!home) {
            LogPrintf("[RevokeHook] Cannot determine HOME\n");
            return false;
        }
        ini_path = std::string(home) + "/.config/RevokeHook/RevokeHook.ini";
    }

    LogPrintf("[RevokeHook] INI path: %s (source: %s)\n",
        ini_path.c_str(), (env_path && env_path[0]) ? "env" : "default");

    // Simple INI parser (no external library)
    {
        FILE *fp = fopen(ini_path.c_str(), "r");
        if (!fp) {
            LogPrintf("[RevokeHook] INI not found: %s\n", ini_path.c_str());
            return false;
        }
        g_ini.clear();
        std::string current_section;
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            // Strip trailing newline/carriage return
            char *end = line + strlen(line);
            while (end > line && (end[-1] == '\n' || end[-1] == '\r')) end--;
            *end = '\0';
            // Skip empty lines and comments
            char *p = line;
            while (*p == ' ' || *p == '\t') p++;
            if (*p == '\0' || *p == '#' || *p == ';') continue;
            // Section header
            if (*p == '[') {
                char *close = strchr(p, ']');
                if (close) {
                    current_section = std::string(p + 1, close);
                }
                continue;
            }
            // Key=Value
            char *eq = strchr(p, '=');
            if (eq) {
                std::string key(p, eq);
                std::string val(eq + 1);
                // Trim
                while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) key.pop_back();
                while (!val.empty() && (val[0] == ' ' || val[0] == '\t')) val.erase(val.begin());
                g_ini[current_section][key] = val;
            }
        }
        fclose(fp);
    }

    g_module_name = "wechat";

    // Wait for target module to load (up to 30 seconds, 100 × 300ms)
    uint64_t module_base = 0;
    for (int i = 0; i < 100; i++) {
        module_base = FindModuleBase(g_module_name.c_str());
        if (module_base != 0) break;
        usleep(300000);
    }
    if (module_base == 0) {
        LogPrintf("[RevokeHook] Module '%s' not found after 30s\n",
            g_module_name.c_str());
        return false;
    }

    g_config_info.basic_info.imgbase       = module_base;
    g_config_info.basic_info.delmsg_offset = (uint64_t)strtoull(g_ini["KeyFunc"]["DelMsgOffset"].c_str(), nullptr, 0);
    g_config_info.basic_info.add2db_offset = (uint64_t)strtoull(g_ini["KeyFunc"]["Add2DBOffset"].c_str(), nullptr, 0);

    std::string anti_self = g_ini["Setting"]["AntiRevokeSelf"];
    g_anti_revoke_self_msg = (anti_self == "true" || anti_self == "1");
    std::string debug_msg = g_ini["Setting"]["OutputDebugMsg"];
    g_output_debug_msg = (debug_msg == "true" || debug_msg == "1");

    LogPrintf("[RevokeHook] Config loaded: %s (module=%s, base=%p)\n",
        ini_path.c_str(), g_module_name.c_str(), (void *)module_base);
    return true;
}

// -----------------------------------------------------------------------
// Entry / Exit (replaces DllMain DLL_PROCESS_ATTACH / DLL_PROCESS_DETACH)
// -----------------------------------------------------------------------

__attribute__((constructor))
static void on_load(void) {
    // Only run in the wechat main process, skip child processes
    // (crashpad_handler, WeChatAppEx, bwrap, etc.)
    char exe_path[256] = {0};
    ssize_t n = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (n > 0) {
        exe_path[n] = '\0';
        const char *base = strrchr(exe_path, '/');
        base = base ? base + 1 : exe_path;
        if (strcmp(base, "wechat") != 0)
            return;
    }

    LogInit();
    g_mem_fd = open("/proc/self/mem", O_RDWR | O_CLOEXEC);
    if (g_mem_fd < 0) {
        LogPrintf("[RevokeHook] Cannot open /proc/self/mem: %s\n",
                  strerror(errno));
        return;
    }

    if (!InitThreadStateTls()) {
        LogPrintf("[RevokeHook] InitThreadStateTls Failed!\n");
        return;
    }

    LogPrintf("[RevokeHook] Reading Config...\n");
    if (!ReadConfig()) return;
    LogPrintf("[RevokeHook] Installing hooks...\n");

    if (!SigBp_Init(1)) {
        LogPrintf("[RevokeHook] SigBp_Init failed!\n");
        return;
    }

    g_bpDelMsg = (void *)(g_config_info.basic_info.imgbase +
                           g_config_info.basic_info.delmsg_offset);
    g_bpAdd2DB = (void *)(g_config_info.basic_info.imgbase +
                           g_config_info.basic_info.add2db_offset);

    if (SigBp_Set(g_bpDelMsg, OnTargetHit) == -1)
        LogPrintf("[RevokeHook] AddBp %p Error\n", g_bpDelMsg);
    else
        LogPrintf("[RevokeHook] AddBp %p OK\n", g_bpDelMsg);

    if (SigBp_Set(g_bpAdd2DB, OnTargetHit) == -1)
        LogPrintf("[RevokeHook] AddBp %p Error\n", g_bpAdd2DB);
    else
        LogPrintf("[RevokeHook] AddBp %p OK\n", g_bpAdd2DB);
}

__attribute__((destructor))
static void on_unload(void) {
    LogPrintf("[RevokeHook] Uninstalling hooks...\n");
    SigBp_Uninit();
    UninitThreadStateTls();

    if (g_mem_fd >= 0) {
        close(g_mem_fd);
        g_mem_fd = -1;
    }
    LogClose();
}
