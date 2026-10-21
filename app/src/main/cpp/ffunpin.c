// FFUnpin native layer — GOT patch for OpenSSL/BoringSSL verify calls made by
// UnityWebRequest / libcurl / Garena SDK inside the Free Fire process.
// Strategy: no inline hooking, no PLT trampolines. We rewrite the GOT slots of
// the verify functions in every loaded ELF (dl_iterate_phdr + DT_RELA walk), so
// every `bl SSL_CTX_set_verify@plt` lands on our stub instead.
// Re-runnable: a watchdog thread re-patches newly dlopen()ed libraries.

#include <jni.h>
#include <android/log.h>
#include <elf.h>
#include <link.h>
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>

#define TAG "FFUnpin"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

// ---------------------------------------------------------------- stubs
static void (*real_set_verify)(void *, int, void *) = NULL;

static void stub_SSL_CTX_set_verify(void *ctx, int mode, void *cb) {
    if (real_set_verify) real_set_verify(ctx, 0 /* SSL_VERIFY_NONE */, NULL);
    LOGI("SSL_CTX_set_verify intercepted (mode=%d -> NONE)", mode);
}
static void stub_SSL_set_verify(void *ssl, int mode, void *cb) {
    LOGI("SSL_set_verify intercepted (mode=%d)", mode);
}
static long stub_SSL_get_verify_result(const void *ssl) { return 0; /* X509_V_OK */ }
static int stub_X509_verify_cert(void *ctx) { return 1; }
static int stub_custom_verify(void *a, int b, void *c) { return 0; /* ssl_verify_ok */ }
static int stub_store_ctx_get_error(void *ctx) { return 0; }
static void stub_store_ctx_set_error(void *ctx, int e) { }
static int stub_store_ctx_get_error_depth(void *ctx) { return 0; }

// ---------------------------------------------------------------- targets
struct target { const char *name; void *fn; };

static const struct target TARGETS[] = {
    {"SSL_CTX_set_verify",           (void *) stub_SSL_CTX_set_verify},
    {"SSL_set_verify",               (void *) stub_SSL_set_verify},
    {"SSL_get_verify_result",        (void *) stub_SSL_get_verify_result},
    {"X509_verify_cert",             (void *) stub_X509_verify_cert},
    {"SSL_CTX_set_custom_verify",    (void *) stub_custom_verify},
    {"SSL_set_custom_verify",        (void *) stub_custom_verify},
    {"X509_STORE_CTX_get_error",     (void *) stub_store_ctx_get_error},
    {"X509_STORE_CTX_set_error",     (void *) stub_store_ctx_set_error},
    {"X509_STORE_CTX_get_error_depth", (void *) stub_store_ctx_get_error_depth},
};
static const int TARGET_COUNT = (int) (sizeof(TARGETS) / sizeof(TARGETS[0]));

// ---------------------------------------------------------------- helpers
static int g_page = 4096;
static int g_patched_total = 0;

static int patch_slot(void *slot, void *value) {
    if (!slot || !value) return -1;
    if (*(void **) slot == value) return 0;                 // already ours
    uintptr_t page = ((uintptr_t) slot) & ~((uintptr_t) g_page - 1);
    if (mprotect((void *) page, (size_t) g_page,
                 PROT_READ | PROT_WRITE) != 0) return -2;
    *(void **) slot = value;
    __builtin___clear_cache((char *) slot, (char *) slot + sizeof(void *));
    mprotect((void *) page, (size_t) g_page, PROT_READ);
    return 1;
}

static const struct target *find_target(const char *name) {
    if (!name) return NULL;
    for (int i = 0; i < TARGET_COUNT; i++)
        if (strcmp(TARGETS[i].name, name) == 0) return &TARGETS[i];
    return NULL;
}

// is this a relocation type that stores a symbol address in a writable slot?
static int is_ptr_reloc(int type) {
    return type == R_AARCH64_JUMP_SLOT || type == R_AARCH64_GLOB_DAT ||
           type == R_AARCH64_ABS64;
}

static void scan_rela(void *base, const ElfW(Rela) *rela, size_t count,
                      const ElfW(Sym) * symtab, const char *strtab,
                      const char *obj) {
    if (!rela || !symtab || !strtab || count == 0) return;
    for (size_t i = 0; i < count; i++) {
        int type = (int) ELF64_R_TYPE(rela[i].r_info);
        if (!is_ptr_reloc(type)) continue;
        unsigned long sym = (unsigned long) ELF64_R_SYM(rela[i].r_info);
        const char *name = strtab + symtab[sym].st_name;
        const struct target *t = find_target(name);
        if (!t) continue;
        void *slot = (void *) ((uintptr_t) base + rela[i].r_offset);
        int rc = patch_slot(slot, t->fn);
        if (rc == 1) {
            g_patched_total++;
            LOGI("GOT patch %s: %s @%p -> %p", obj ? obj : "?", name, slot, t->fn);
        }
    }
}

static int phdr_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void) size; (void) data;
    uintptr_t base = (uintptr_t) info->dlpi_addr;
    const char *obj = info->dlpi_name && info->dlpi_name[0] ? info->dlpi_name : "main";

    const ElfW(Dyn) *dyn = NULL;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dyn = (const ElfW(Dyn) *) (base + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return 0;

    const ElfW(Sym) *symtab = NULL;
    const char *strtab = NULL;
    const ElfW(Rela) *jmprel = NULL, *rela = NULL;
    size_t jmprel_sz = 0, rela_sz = 0;

    for (const ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_SYMTAB:   symtab = (const ElfW(Sym) *) d->d_un.d_ptr; break;
            case DT_STRTAB:   strtab = (const char *) d->d_un.d_ptr; break;
            case DT_JMPREL:   jmprel = (const ElfW(Rela) *) d->d_un.d_ptr; break;
            case DT_PLTRELSZ: jmprel_sz = d->d_un.d_val; break;
            case DT_RELA:     rela = (const ElfW(Rela) *) d->d_un.d_ptr; break;
            case DT_RELASZ:   rela_sz = d->d_un.d_val; break;
            default: break;
        }
    }

    // plain relocations may also be RELA (older NDK output / .rela.dyn)
    if (rela_sz && !rela) {
        for (const ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; d++) {
            if (d->d_tag == DT_REL) {
                // REL (no addend) — walk manually with 4-byte entries is out of
                // scope; Android arm64 ships RELA only.
                break;
            }
        }
    }

    scan_rela((void *) base, jmprel, jmprel_sz / sizeof(ElfW(Rela)),
              symtab, strtab, obj);
    scan_rela((void *) base, rela, rela_sz / sizeof(ElfW(Rela)),
              symtab, strtab, obj);
    return 0;
}

static void patch_all(void) {
    dl_iterate_phdr(phdr_cb, NULL);
}

// grab the original setter once so we can still honour the call (mode=NONE)
static void resolve_originals(void) {
    if (!real_set_verify) {
        real_set_verify = (void (*)(void *, int, void *)) dlsym(RTLD_DEFAULT, "SSL_CTX_set_verify");
        if (real_set_verify) LOGI("real SSL_CTX_set_verify = %p", real_set_verify);
    }
}

// Libraries load lazily (UnityWebRequest, libcurl, Garena SDK). Keep sweeping
// for 3 minutes after process start, then stop (cheap, no busy loop).
static void *watchdog(void *arg) {
    (void) arg;
    int last = -1;
    for (int i = 0; i < 360; i++) {
        resolve_originals();
        patch_all();
        if (g_patched_total != last) {
            last = g_patched_total;
            LOGI("total GOT slots patched: %d", g_patched_total);
        }
        usleep(500 * 1000);
    }
    LOGI("watchdog done, patched=%d", g_patched_total);
    return NULL;
}

// ---------------------------------------------------------------- JNI
__attribute__((constructor)) static void on_load(void) {
    g_page = getpagesize();
    LOGI("libffunpin loaded (constructor)");
}

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) vm; (void) reserved;
    LOGI("JNI_OnLoad — arming native unpin");
    resolve_originals();
    patch_all();
    pthread_t th;
    if (pthread_create(&th, NULL, watchdog, NULL) == 0) pthread_detach(th);
    LOGI("native armed, immediate patches=%d", g_patched_total);
    return JNI_VERSION_1_6;
}
