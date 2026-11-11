// qemu_harness.c — исполнение userland-кода PS5 (eboot.elf) как процесса Linux.
//
// Идея: eboot от PS5 — обычный x86-64 ELF (FreeBSD ABI), но в нём НЕТ инструкций
// syscall: весь системный слой идёт через импорты libkernel/libc. Значит его
// можно запустить как обычный Linux-процесс, если:
//   1) разложить PT_LOAD по их p_vaddr (mmap MAP_FIXED),
//   2) заменить каждый слот GOT на мок-шим, возвращающий 0 и считающий вызовы,
//   3) дать стек, argc/argv и TLS (arch_prctl ARCH_SET_FS).
// Дальше код исполняется либо нативно (хост умеет AVX2), либо под qemu-x86_64
// (TCG 10.2.2 умеет AVX/AVX2) — снимая ограничение Unicorn 2.1.4.
//
// Использование:
//   ./qemu_harness <eboot.elf> [start_pc_hex|entry|main]
// По умолчанию start = main (0xc7e5c0), т.к. страница 0 недоступна без qemu -B.
// Импорты логируются в страницу-счётчик: dump после падения/выхода.
//
// Считать инструкции: запустить под
//   qemu-x86_64 -B 0x4000000000 -one-insn-per-tb -d exec -dfilter 0x0+0xafb7470 ...
// и посчитать строки "Trace" — это ровно исполненные инструкции в диапазоне
// образа PS5 (dfilter отсекает лоадер/моки/стек).

#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <asm/prctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <ucontext.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#define PAGE 0x1000ULL
#define MOCK_BASE 0x30000000ULL     /* < 4 GiB: нужен 32-битный абсолютный адрес */
#define LOG_BASE 0x20000000ULL      /* < 4 GiB */
#define SCRATCH_BASE 0x600000000ULL   /* 16 МБ нулевой «кучи» для моков */
#define SCRATCH_SIZE 0x1000000ULL
#define STACK_BASE 0x700000000ULL
#define STACK_SIZE 0x800000ULL
#define TLS_SIZE 0x4000ULL

static uint8_t *g_file;
static size_t g_filesz;
static int g_nplt;
static int g_nslots = 0;   /* число установленных трамплинов */
static int g_low_skipped;

/* ---- резолв импортов по NID в реальные anyps5-библиотеки (Linux .so) ---- */
#define TRAMP_SIZE 32
#define MAX_IMPORTS 1024
#define MAX_LIBS 64
struct imp_ent {
    uint64_t stub, got;
    char lib[64], nid[40];
    int weak;
};
static struct imp_ent g_imp[MAX_IMPORTS];
static int g_nimp;
static const char *g_libdir;
static int g_resolved, g_mocked, g_nomapping;
static int g_no_real; /* PS5_NO_REAL=1 -> все импорты моки */
static int g_mock_ptr;
static int g_seed_vtable; /* PS5_MOCK_PTR=1 -> мок возвращает указатель на нулевую кучу */
static char g_lib_names[MAX_LIBS][64];
static void *g_lib_handles[MAX_LIBS];
static int g_nlibs;

struct plt_ent {
    uint64_t stub, got;
    uint32_t idx;
};
static struct plt_ent *g_plt;

static void die(const char *msg) {
    fprintf(stderr, "[harness][fatal] %s (errno=%d)\n", msg, errno);
    _exit(3);
}

static void info(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void info(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    fflush(stdout);
}

static void map_fixed(uint64_t addr, uint64_t size, int prot) {
    void *p = mmap((void *)(uintptr_t)addr, size, prot,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p == MAP_FAILED && errno == EEXIST) {
        p = mmap((void *)(uintptr_t)addr, size, prot,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    }
    if (p == MAP_FAILED || (uint64_t)(uintptr_t)p != addr)
        die("mmap MAP_FIXED не удался");
}

static uint64_t align_down(uint64_t x) { return x & ~(PAGE - 1); }
static uint64_t align_up(uint64_t x) { return (x + PAGE - 1) & ~(PAGE - 1); }

/* ------------------------------------------------------------------ */
/* загрузка PT_LOAD                                                    */
/* ------------------------------------------------------------------ */
static uint64_t g_low_from; /* адрес, с которого реально отображён низ */

static int cmp_reg(const void *a, const void *b) {
    const uint64_t *x = a, *y = b;
    return x[0] < y[0] ? -1 : x[0] > y[0];
}

static int load_segments(const Elf64_Ehdr *eh) {
    const Elf64_Phdr *ph = (const Elf64_Phdr *)(g_file + eh->e_phoff);
    int nloads = 0;
    uint64_t total = 0;
    /* 1. объединяем страничные покрытия PT_LOAD (в eboot они пересекаются) */
    uint64_t reg[32][2];
    int nreg = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD || ph[i].p_memsz == 0)
            continue;
        reg[nreg][0] = align_down(ph[i].p_vaddr);
        reg[nreg][1] = align_up(ph[i].p_vaddr + ph[i].p_memsz);
        nreg++;
    }
    qsort(reg, nreg, sizeof(reg[0]), cmp_reg);
    int merged = 0;
    for (int i = 0; i < nreg; i++) {
        if (merged > 0 && reg[i][0] <= reg[merged - 1][1]) {
            if (reg[i][1] > reg[merged - 1][1])
                reg[merged - 1][1] = reg[i][1];
        } else {
            reg[merged][0] = reg[i][0];
            reg[merged][1] = reg[i][1];
            merged++;
        }
    }
    /* 2. mmap каждого объединённого региона */
    for (int i = 0; i < merged; i++) {
        uint64_t base = reg[i][0], end = reg[i][1];
        uint64_t mapbase = base;
        void *p = mmap((void *)(uintptr_t)mapbase, end - mapbase,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (p == MAP_FAILED && base < 0x10000ULL) {
            mapbase = 0x10000ULL;
            p = mmap((void *)(uintptr_t)mapbase, end - mapbase,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
            if (p == MAP_FAILED) {
                p = mmap((void *)(uintptr_t)mapbase, end - mapbase,
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            }
            if (p == MAP_FAILED)
                die("mmap низкого региона не удался");
            g_low_from = mapbase;
            g_low_skipped = 1;
        } else if (p == MAP_FAILED) {
            die("mmap региона не удался");
        }
        if ((uint64_t)(uintptr_t)p != mapbase)
            die("mmap вернул не тот адрес");
        total += end - mapbase;
        info("[harness] mmap %#llx..%#llx (%.1f МБ)%s",
             (unsigned long long)mapbase, (unsigned long long)end,
             (end - mapbase) / 1e6,
             mapbase != base ? " [низ пропущен: mmap_min_addr]" : "");
    }
    /* 3. копируем данные файла по порядку phdr (поздние перекрывают ранние) */
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD || ph[i].p_filesz == 0)
            continue;
        uint64_t va = ph[i].p_vaddr, n = ph[i].p_filesz;
        uint64_t src = ph[i].p_offset, dst = va;
        if (g_low_from && va < g_low_from) {
            uint64_t skip = g_low_from - va;
            if (skip >= n)
                continue;
            src += skip;
            dst += skip;
            n -= skip;
        }
        memcpy((void *)(uintptr_t)dst, g_file + src, n);
        nloads++;
        total += n;
    }
    info("[harness] загружено PT_LOAD: %d, скопировано с диска: %.1f МБ",
         nloads, total / 1e6);
    return nloads;
}

/* ------------------------------------------------------------------ */
/* скан PLT-заглушек PS5: ff 25 <disp32> 68 <imm32> e9 <rel32>         */
/* ------------------------------------------------------------------ */
static void scan_plt(const Elf64_Ehdr *eh) {
    const Elf64_Phdr *ph = (const Elf64_Phdr *)(g_file + eh->e_phoff);
    int cap = 4096;
    g_plt = calloc(cap, sizeof(*g_plt));
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD || !(ph[i].p_flags & PF_X) || !ph[i].p_filesz)
            continue;
        const uint8_t *b = g_file + ph[i].p_offset;
        uint64_t n = ph[i].p_filesz;
        for (uint64_t k = 0; k + 16 <= n; k++) {
            if (b[k] != 0xff || b[k + 1] != 0x25 || b[k + 6] != 0x68 ||
                b[k + 11] != 0xe9)
                continue;
            int32_t disp;
            uint32_t imm;
            memcpy(&disp, b + k + 2, 4);
            memcpy(&imm, b + k + 7, 4);
            if (g_nplt == cap) {
                cap *= 2;
                g_plt = realloc(g_plt, cap * sizeof(*g_plt));
            }
            g_plt[g_nplt].stub = ph[i].p_vaddr + k;
            g_plt[g_nplt].got = ph[i].p_vaddr + k + 6 + disp;
            g_plt[g_nplt].idx = imm;
            g_nplt++;
            k += 15;
        }
    }
    info("[harness] PLT-заглушек найдено: %d", g_nplt);
}

/* ------------------------------------------------------------------ */
/* мок-шимы импортов: 16-байтные трамплины, считающие вызовы           */
/* ------------------------------------------------------------------ */
static void parse_manifest(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        info("[harness] манифест импортов НЕ открыт (%s): все импорты -> мок", path);
        return;
    }
    char line[512];
    while (fgets(line, sizeof line, f)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;
        unsigned long long stub = 0, got = 0, rel = 0;
        char lib[64] = {0}, nid[40] = {0};
        int weak = 0;
        int n = sscanf(line, "%llx\t%llx\t%llx\t%63[^\t]\t%39[^\t]\t%d",
                       &stub, &got, &rel, lib, nid, &weak);
        if (n < 6)
            n = sscanf(line, "%llx\t%llx\t%llx\t%63[^\t]\t%39s",
                       &stub, &got, &rel, lib, nid);
        if (n < 5 || g_nimp >= MAX_IMPORTS)
            continue;
        g_imp[g_nimp].stub = stub;
        g_imp[g_nimp].got = got;
        snprintf(g_imp[g_nimp].lib, sizeof g_imp[g_nimp].lib, "%s", lib);
        snprintf(g_imp[g_nimp].nid, sizeof g_imp[g_nimp].nid, "%s", nid);
        g_imp[g_nimp].weak = weak;
        g_nimp++;
    }
    fclose(f);
    info("[harness] манифест импортов: %d записей (%s)", g_nimp, path);
}

static const struct imp_ent *imp_by_stub(uint64_t stub) {
    for (int i = 0; i < g_nimp; i++)
        if (g_imp[i].stub == stub)
            return &g_imp[i];
    return NULL;
}

static void *lib_open(const char *lib) {
    if (!lib || !lib[0])
        return NULL;
    for (int i = 0; i < g_nlibs; i++)
        if (strcmp(g_lib_names[i], lib) == 0)
            return g_lib_handles[i];
    char path[512];
    snprintf(path, sizeof path, "%s/%s", g_libdir, lib);
    void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (g_nlibs < MAX_LIBS) {
        snprintf(g_lib_names[g_nlibs], sizeof g_lib_names[0], "%s", lib);
        g_lib_handles[g_nlibs] = h;
        g_nlibs++;
    }
    if (!h)
        info("[harness] dlopen НЕ удался: %s", dlerror());
    return h;
}

/* Трамплин на каждый PLT-слот (32 байта):
     ff 04 25 <logaddr>     inc dword ptr [logaddr]      ; счётчик вызовов
     [если найдено] 48 b8 <imm64> ff e0   mov rax,fn; jmp rax  (хвостовой вызов)
     [иначе]        31 c0 c3              xor eax,eax; ret       (мок: вернуть 0) */
static void seed_fake_vtable(void) {
    /* Экспериментальный хак: код PS5 после инициализации дергает методы через
       глобальный объект, который в настоящем загрузчике заполняется runtime'ом
       (у anyps5 — Aps5CallGuestEntry/инициализаторами модулей). Здесь мы
       подкладываем в такой объект таблицу из адресов "вернуть 0". */
    map_fixed(SCRATCH_BASE, SCRATCH_SIZE, PROT_READ | PROT_WRITE);
    uint64_t *vt = (uint64_t *)(uintptr_t)SCRATCH_BASE;
    uint64_t ret0 = MOCK_BASE + 0x80000; /* отдельный stub: xor eax,eax; ret */
    map_fixed(MOCK_BASE + 0x80000, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC);
    uint8_t *st = (uint8_t *)(uintptr_t)ret0;
    st[0] = 0x31; st[1] = 0xc0; st[2] = 0xc3;
    for (int i = 0; i < 0x400; i++)
        vt[i] = ret0;
    /* глобалы рядом с 0x8456d90 (их заполняет ранняя инициализация PS5) */
    for (uint64_t a = 0x8456d90ULL; a <= 0x8456dd8ULL; a += 8)
        *(uint64_t *)(uintptr_t)a = SCRATCH_BASE;
    info("[harness] хак: подложена fake-vtable в %#llx, глобалы 0x8456d90.."
         "0x8456dd8 прошиты", (unsigned long long)SCRATCH_BASE);
}

static void install_imports(void) {
    if (g_mock_ptr)
        map_fixed(SCRATCH_BASE, SCRATCH_SIZE, PROT_READ | PROT_WRITE);
    uint64_t size = align_up((uint64_t)g_nplt * TRAMP_SIZE);
    map_fixed(MOCK_BASE, size, PROT_READ | PROT_WRITE | PROT_EXEC);
    map_fixed(LOG_BASE, PAGE, PROT_READ | PROT_WRITE);
    uint8_t *code = (uint8_t *)(uintptr_t)MOCK_BASE;
    memset(code, 0x90, size);
    for (int i = 0; i < g_nplt; i++) {
        uint8_t *c = code + (uint64_t)i * TRAMP_SIZE;
        uint32_t logaddr = (uint32_t)(LOG_BASE + 4 * i);
        c[0] = 0xff; c[1] = 0x04; c[2] = 0x25;   /* inc dword [logaddr] */
        memcpy(c + 3, &logaddr, 4);
        const struct imp_ent *e = imp_by_stub(g_plt[i].stub);
        void *fn = NULL;
        if (g_no_real)
            e = NULL; /* режим чистых моков: ни одного реального вызова */
        if (e && e->lib[0] && strcmp(e->lib, "-") != 0 &&
            e->nid[0] && strcmp(e->nid, "-") != 0) {
            void *h = lib_open(e->lib);
            if (h)
                fn = dlsym(h, e->nid);
        }
        if (fn) {
            c[7] = 0x48; c[8] = 0xb8;             /* mov rax, imm64 */
            memcpy(c + 9, &fn, 8);
            c[17] = 0xff; c[18] = 0xe0;           /* jmp rax */
            g_resolved++;
        } else {
            if (g_mock_ptr) {
                /* mov rax, SCRATCH_BASE; ret — «функция вернула указатель» */
                c[7] = 0x48; c[8] = 0xb8;
                uint64_t pv = SCRATCH_BASE;
                memcpy(c + 9, &pv, 8);
                c[17] = 0xc3;
            } else {
                c[7] = 0x31; c[8] = 0xc0; c[9] = 0xc3; /* xor eax,eax; ret */
            }
            if (e || g_no_real)
                g_mocked++;
            else
                g_nomapping++;
        }
        memset(c + 19, 0xcc, TRAMP_SIZE - 19);
        *(uint64_t *)(uintptr_t)g_plt[i].got = MOCK_BASE + (uint64_t)i * TRAMP_SIZE;
        g_nslots = i + 1;
    }
    info("[harness] режим моков: %s", g_mock_ptr ? "возврат указателя на нулевую кучу"
                                                   : "возврат 0");
    info("[harness] импортов: %d всего; резолвлено в реальные функции anyps5: %d, "
         "моков (вернут 0): %d, без манифеста: %d",
         g_nslots, g_resolved, g_mocked, g_nomapping);
    info("[harness] библиотек anyps5 открыто: %d из %s", g_nlibs, g_libdir);
}

/* ------------------------------------------------------------------ */
/* точка входа: стек, argv, TLS, прыжок                                */
/* ------------------------------------------------------------------ */
static uint64_t setup_stack(void) {
    map_fixed(STACK_BASE, STACK_SIZE, PROT_READ | PROT_WRITE);
    uint64_t top = STACK_BASE + STACK_SIZE;
    uint64_t str = top - 0x400;
    uint64_t argc_p = top - 0x100;
    uint64_t argv_p = top - 0xF8;
    memcpy((void *)(uintptr_t)str, "eboot.elf", 10);
    *(uint64_t *)(uintptr_t)argc_p = 1;
    *(uint64_t *)(uintptr_t)argv_p = str;
    *(uint64_t *)(uintptr_t)(argv_p + 8) = 0;
    uint64_t rsp = top - 0x1000;
    info("[harness] стек: rsp=%#llx argc_p=%#llx argv_p=%#llx argv[0]=\"eboot.elf\"",
         (unsigned long long)rsp, (unsigned long long)argc_p,
         (unsigned long long)argv_p);
    return rsp;
}

static uint64_t g_tls_base;

/* Важно: FS нельзя переключать заранее — glibc держит в FS errno и canary,
   поэтому arch_prctl делается в самом конце, непосредственно перед прыжком,
   и после него никаких вызовов libc нет. */
static void setup_tls(void) {
    void *p = mmap(NULL, TLS_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        die("TLS mmap");
    memset(p, 0, TLS_SIZE);
    g_tls_base = (uint64_t)(uintptr_t)p + 0x40;
    info("[harness] TLS/FS_BASE=%#llx (переключим прямо перед прыжком)",
         (unsigned long long)g_tls_base);
}

static void enter_guest_tls(void) {
    if (syscall(SYS_arch_prctl, ARCH_SET_FS, (unsigned long)g_tls_base) != 0)
        _exit(3);
}

/* ---- «сырой» вывод: после смены FS нельзя звать libc (errno/canary в FS) ---- */
static char g_buf[2048];
static int g_len;
static void rb_ch(char c) { if (g_len < (int)sizeof g_buf - 1) g_buf[g_len++] = c; }
static void rb_str(const char *s) { while (*s) rb_ch(*s++); }
static void rb_hex(uint64_t v) {
    static const char d[] = "0123456789abcdef";
    char t[20];
    int i = 0;
    rb_str("0x");
    if (!v) { rb_ch('0'); return; }
    while (v) { t[i++] = d[v & 15]; v >>= 4; }
    while (i) rb_ch(t[--i]);
}
static void rb_dec(uint64_t v) {
    char t[24];
    int i = 0;
    if (!v) { rb_ch('0'); return; }
    while (v) { t[i++] = (char)('0' + v % 10); v /= 10; }
    while (i) rb_ch(t[--i]);
}
static void rb_flush(void) {
    if (g_len) { syscall(SYS_write, 1, g_buf, (unsigned long)g_len); g_len = 0; }
}

static uint64_t g_import_total;

static void dump_import_log_raw(void) {
    uint32_t *log = (uint32_t *)(uintptr_t)LOG_BASE;
    uint64_t total = 0;
    for (int i = 0; i < g_nslots; i++)
        total += log[i];
    g_import_total = total;
    rb_str("[harness][imports] всего вызовов моков: ");
    rb_dec(total);
    rb_str(", ненулевых слотов: ");
    int nz = 0;
    for (int i = 0; i < g_nslots; i++)
        nz += log[i] != 0;
    rb_dec((uint64_t)nz);
    rb_ch('\n');
    rb_flush();
    int shown = 0;
    for (int i = 0; i < g_nslots && shown < 25; i++) {
        if (!log[i])
            continue;
        rb_str("[harness][imports]   слот ");
        rb_dec((uint64_t)i);
        rb_str(": ");
        rb_dec(log[i]);
        rb_str(" вызовов, stub=");
        uint64_t stub = (i < g_nplt) ? g_plt[i].stub : 0;
        rb_hex(stub);
        const struct imp_ent *e = imp_by_stub(stub);
        if (e) {
            rb_str("  ");
            rb_str(e->lib[0] ? e->lib : "(weak)");
            rb_ch(':');
            rb_str(e->nid);
            /* реальная функция или мок — по байтам трамплина */
            uint8_t *c = (uint8_t *)(uintptr_t)(MOCK_BASE + (uint64_t)i * TRAMP_SIZE);
            rb_str(c[7] == 0x48 ? " -> real" : " -> mock");
        }
        rb_ch('\n');
        rb_flush();
        shown++;
    }
}

static void sig_handler(int sig, siginfo_t *si, void *uctx) {
    ucontext_t *uc = (ucontext_t *)uctx;
    uint64_t rip = (uint64_t)uc->uc_mcontext.gregs[REG_RIP];
    rb_str("[harness][signal] сигнал ");
    rb_dec((uint64_t)sig);
    rb_str(" (");
    rb_str(sig == SIGSEGV ? "SIGSEGV" : sig == SIGILL ? "SIGILL"
           : sig == SIGBUS ? "SIGBUS" : sig == SIGFPE ? "SIGFPE" : "sig");
    rb_str("): rip=");
    rb_hex(rip);
    rb_str(" addr=");
    rb_hex((uint64_t)(uintptr_t)si->si_addr);
    rb_ch('\n');
    rb_flush();
    rb_str("[harness][regs] rax="); rb_hex((uint64_t)uc->uc_mcontext.gregs[REG_RAX]);
    rb_str(" rbx="); rb_hex((uint64_t)uc->uc_mcontext.gregs[REG_RBX]);
    rb_str(" rcx="); rb_hex((uint64_t)uc->uc_mcontext.gregs[REG_RCX]);
    rb_str(" rdx="); rb_hex((uint64_t)uc->uc_mcontext.gregs[REG_RDX]);
    rb_ch('\n'); rb_flush();
    rb_str("[harness][regs] rsi="); rb_hex((uint64_t)uc->uc_mcontext.gregs[REG_RSI]);
    rb_str(" rdi="); rb_hex((uint64_t)uc->uc_mcontext.gregs[REG_RDI]);
    rb_str(" rbp="); rb_hex((uint64_t)uc->uc_mcontext.gregs[REG_RBP]);
    rb_str(" rsp="); rb_hex((uint64_t)uc->uc_mcontext.gregs[REG_RSP]);
    rb_ch('\n'); rb_flush();
    dump_import_log_raw();
    rb_str("[harness][done] останов по сигналу\n");
    rb_flush();
    syscall(SYS_exit_group, 42);
    for (;;) {}
}

static void install_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sig_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    for (int s = 0; s < NSIG; s++)
        sigaction(s, &sa, NULL);
}

/* System V: arg1=rdi(pc), arg2=rsi(rdi), arg3=rdx(rsi), arg4=rcx(rdx),
   arg5=r8(rsp) */
__attribute__((naked, noreturn)) static void jump(uint64_t pc, uint64_t rdi,
                                                  uint64_t rsi, uint64_t rdx,
                                                  uint64_t rsp) {
    __asm__ volatile("mov %rdi, %rax\n\t" /* pc */
                     "mov %r8, %r9\n\t"   /* rsp */
                     "mov %rsi, %rdi\n\t"
                     "mov %rdx, %rsi\n\t"
                     "mov %rcx, %rdx\n\t"
                     "mov %r9, %rsp\n\t"
                     "jmp *%rax\n\t");
}

/* ------------------------------------------------------------------ */
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) {
        fprintf(stderr, "usage: %s <eboot.elf> [start_pc_hex|entry]\n", argv[0]);
        return 2;
    }
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0)
        die("открыть eboot.elf");
    struct stat st;
    fstat(fd, &st);
    g_filesz = st.st_size;
    g_file = mmap(NULL, g_filesz, PROT_READ, MAP_PRIVATE, fd, 0);
    if (g_file == MAP_FAILED)
        die("mmap файла");
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)g_file;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 || eh->e_ident[EI_CLASS] != ELFCLASS64)
        die("не ELF64");
    info("[harness] файл=%s размер=%zu e_type=%#x e_machine=%#x entry=%#llx "
         "phnum=%d",
         argv[1], g_filesz, eh->e_type, eh->e_machine,
         (unsigned long long)eh->e_entry, eh->e_phnum);

    g_no_real = getenv("PS5_NO_REAL") != NULL;
    g_mock_ptr = getenv("PS5_MOCK_PTR") != NULL;
    g_seed_vtable = getenv("PS5_SEED_VTABLE") != NULL;
    g_libdir = getenv("PS5_LIBDIR");
    if (!g_libdir || !g_libdir[0])
        g_libdir = "/home/oleg/Документы/ps5semulator/anyps5/libs";
    const char *manifest = (argc > 3) ? argv[3] : "output/imports.tsv";
    load_segments(eh);
    scan_plt(eh);
    parse_manifest(manifest);
    install_imports();
    if (g_seed_vtable)
        seed_fake_vtable();
    uint64_t rsp = setup_stack();
    setup_tls();
    install_signals();

    uint64_t start;
    const char *mode;
    if (argc > 2 && strcmp(argv[2], "entry") == 0) {
        start = eh->e_entry;
        mode = "entry (e_entry)";
    } else if (argc > 2) {
        start = strtoull(argv[2], NULL, 0);
        mode = "явный pc";
    } else {
        start = 0xc7e5c0ULL; /* main(argc, argv, 0) по статическому разбору */
        mode = "main=0xc7e5c0";
    }
    uint64_t argc_p = STACK_BASE + STACK_SIZE - 0x100;
    uint64_t argv_p = STACK_BASE + STACK_SIZE - 0xF8;
    info("[harness] старт: mode=%s pc=%#llx RDI(argc_p)=%#llx "
         "RSI(argv_p)=%#llx RDX=0",
         mode, (unsigned long long)start, (unsigned long long)argc_p,
         (unsigned long long)argv_p);
    if (g_low_skipped && start < 0x10000ULL) {
        info("[harness] ОШИБКА: start < 0x10000 не отображён (нужен qemu -B)");
        return 2;
    }
    info("[harness] --- пошли ---");
    /* FS не переключаем: настоящие anyps5-функции из .so используют TLS glibc
       (errno и т.п.); переключение FS на гостевую страницу ломает их.
       Переключение доступно только для чистых мок-прогонов. */
    if (getenv("PS5_USE_GUEST_TLS"))
        enter_guest_tls();
    jump(start, argc_p, argv_p, 0, rsp);
}