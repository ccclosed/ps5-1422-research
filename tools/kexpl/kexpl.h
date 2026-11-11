/* kexpl.h — минимальное freestanding-окружение для payload-триггеров PS5.
 *
 * Почему не SDK: ps5-payload-dev/sdk собран под clang-18/lld-18 (bin/prospero-clang —
 * шелл-обёртка над host-clang; в системе clang/lld НЕТ, root для установки нет,
 * pip ziglang не скачался через DPI-прокси). Поэтому триггеры — freestanding:
 * gcc -nostdlib, никакой libc/libkernel, все вызовы — raw syscall instruction.
 * Полученный ELF64 статический ET_EXEC — elfldr умеет и ET_EXEC (elfldr.c:172-178).
 *
 * Syscall ABI PS5/FreeBSD x86-64: rax=номер, rdi/rsi/rdx/r10/r8/r9=аргументы,
 * возврат в rax, при ошибке CF=1 и rax=errno.
 */
#ifndef KEXPL_H
#define KEXPL_H

typedef unsigned long  u64;
typedef long           i64;
typedef unsigned int   u32;
typedef int            i32;
typedef unsigned char  u8;

/* --- номера syscall'ов: сверены с нашим дампом fw/sysent-13.60.json (735 записей) --- */
#define SYS_exit            1
#define SYS_fork            2
#define SYS_read            3
#define SYS_write           4
#define SYS_open            5
#define SYS_close           6
#define SYS_wait4           7
#define SYS_getpid          20
#define SYS_kill            37
#define SYS_ioctl           54
#define SYS_socket          97
#define SYS_setsockopt      105
#define SYS_socketpair      135
#define SYS_mkdir           136
#define SYS_nanosleep       240
#define SYS__umtx_op        454
#define SYS_mmap            477
#define SYS_aio_submit      661   /* 0x295 */
#define SYS_aio_multi_delete 662  /* 0x296 Prolapse */
#define SYS_aio_multi_wait  663   /* 0x297 Relapse  */
#define SYS_aio_multi_poll  664   /* 0x298 */
#define SYS_aio_get_data    665   /* 0x299 */
#define SYS_aio_multi_cancel 666  /* 0x29A */
#define SYS_aio_submit_cmd  669   /* 0x29D */
#define SYS_aio_init        670   /* 0x29E */

/* --- errno (FreeBSD) --- */
#define EPERM    1
#define ENOENT   2
#define EFAULT  14
#define EINVAL  22
#define ENOTSUP 45
#define EOPNOTSUPP 45
#define EOPNOTSUP 45
#define EWOULDBLOCK 35
#define EAGAIN  35

/* --- op/флаги --- */
#define UMTX_OP_SHM       25   /* sys/sys/umtx.h releng/11.4:99 */
#define UMTX_SHM_CREAT    0x0001
#define UMTX_SHM_LOOKUP   0x0002
#define UMTX_SHM_DESTROY  0x0004
#define UMTX_SHM_ALIVE    0x0008

#define IPPROTO_IPV6      41
#define IPV6_MSFILTER     74   /* sys/netinet6/in6.h releng/11.4:504 */
#define MCAST_INCLUDE     1
#define MCAST_EXCLUDE     2

#define AF_INET6          28
#define SOCK_DGRAM        2
#define SOCK_STREAM       1
#define AF_UNIX           1
#define SOL_SOCKET        0xffff
#define O_WRONLY          0x0001
#define O_CREAT           0x0200
#define O_APPEND          0x0008

/* ---- сам syscall ---- */
static inline i64 sys0(i64 n) {
    i64 r; u8 err;
    __asm__ volatile("syscall; setc %1" : "=a"(r), "=qm"(err) : "a"(n) : "rcx","r11","memory");
    return err ? -r : r;
}
static inline i64 sys1(i64 n, i64 a) {
    i64 r; u8 err;
    __asm__ volatile("syscall; setc %1" : "=a"(r), "=qm"(err) : "a"(n),"D"(a) : "rcx","r11","memory");
    return err ? -r : r;
}
static inline i64 sys2(i64 n, i64 a, i64 b) {
    i64 r; u8 err;
    __asm__ volatile("syscall; setc %1" : "=a"(r), "=qm"(err) : "a"(n),"D"(a),"S"(b) : "rcx","r11","memory");
    return err ? -r : r;
}
static inline i64 sys3(i64 n, i64 a, i64 b, i64 c) {
    i64 r; u8 err;
    __asm__ volatile("syscall; setc %1" : "=a"(r), "=qm"(err) : "a"(n),"D"(a),"S"(b),"d"(c) : "rcx","r11","memory");
    return err ? -r : r;
}
static inline i64 sys4(i64 n, i64 a, i64 b, i64 c, i64 d) {
    register i64 r10 __asm__("r10") = d;
    i64 r; u8 err;
    __asm__ volatile("syscall; setc %1" : "=a"(r), "=qm"(err) : "a"(n),"D"(a),"S"(b),"d"(c),"r"(r10) : "rcx","r11","memory");
    return err ? -r : r;
}
static inline i64 sys5(i64 n, i64 a, i64 b, i64 c, i64 d, i64 e) {
    register i64 r10 __asm__("r10") = d;
    register i64 r8  __asm__("r8")  = e;
    i64 r; u8 err;
    __asm__ volatile("syscall; setc %1" : "=a"(r), "=qm"(err) : "a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8) : "rcx","r11","memory");
    return err ? -r : r;
}

/* ---- лог в /data/kexpl-<tag>.log (payload на консоли пишет в /data: так делает и
 * relapse-offset-dumper: OUT_DIR "/data/relapse_dump"), фолбэк — /tmp ---- */
static int  g_fd = -1;
static char g_buf[512];
static int  g_len = 0;

static inline int str_len(const char *s){ int n=0; while(s[n]) n++; return n; }
static inline void buf_putc(char c){ if(g_len < (int)sizeof(g_buf)-1) g_buf[g_len++]=c; }
static inline void log_s(const char *s){ while(*s) buf_putc(*s++); }
static inline void log_l(i64 v){
    char t[24]; int i=0; unsigned long u = v<0 ? (unsigned long)-v : (unsigned long)v;
    if(v<0) buf_putc('-');
    if(!u) t[i++]='0';
    while(u){ t[i++] = '0' + (u%10); u/=10; }
    while(i) buf_putc(t[--i]);
}
static inline void log_h(u64 v){
    char t[20]; int i=0;
    log_s("0x");
    if(!v) { buf_putc('0'); return; }
    while(v && i<18){ int d=(int)(v & 0xf); t[i++] = (char)(d<10 ? '0'+d : 'a'+d-10); v>>=4; }
    while(i) buf_putc(t[--i]);
}
static inline void log_flush(int tag){
    if(g_fd < 0) return;
    sys3(SYS_write, g_fd, (i64)g_buf, g_len);
    g_len = 0;
    const char nl='\n'; sys3(SYS_write, g_fd, (i64)&nl, 1);
    (void)tag;
}
/* tag: 1 = инициализация; возвращает 0 если лог открыт */
static inline int klog_init(const char *name, int tag){
    char p[128]; int i=0; const char *a="/data/"; const char *b="-";
    while(*a) { p[i++]=*a++; }
    while(*b) { p[i++]=*b++; }
    while(*name) { p[i++]=*name++; }
    p[i++]='.'; p[i++]='l'; p[i++]='o'; p[i++]='g'; p[i]=0;
    g_fd = (int)sys3(SYS_open, (i64)p, O_WRONLY|O_CREAT|O_APPEND, 0644);
    if(g_fd < 0){
        char q[128]; i=0; const char *c="/tmp/";
        while(*c) { q[i++]=*c++; }
        while(*name) { q[i++]=*name++; }
        q[i++]='.'; q[i++]='l'; q[i++]='o'; q[i++]='g'; q[i]=0;
        g_fd = (int)sys3(SYS_open, (i64)q, O_WRONLY|O_CREAT|O_APPEND, 0644);
    }
    (void)tag;
    return g_fd < 0 ? -1 : 0;
}
static inline void log_tag(const char *t){ log_s("["); log_s(t); log_s("] "); }

static inline void zero_mem(void *p, u64 n){ u8 *b=(u8*)p; for(u64 i=0;i<n;i++) b[i]=0; }

static inline void sleep_us(i64 us){
    long ts[2]; ts[0] = us/1000000; ts[1] = (us%1000000)*1000;
    sys2(SYS_nanosleep, (i64)ts, 0);
}

/* ---- точка входа: без crt ---- */
extern int trig_main(void);
void _start(void){
    int rc = trig_main();
    sys1(SYS_exit, rc);
    for(;;){}
}
#endif
