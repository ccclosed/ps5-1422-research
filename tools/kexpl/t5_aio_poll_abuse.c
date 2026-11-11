/* t5_aio_poll_abuse.c — probe валидации аргументов Sony-AIO (syscalls 663/664/665).
 * Мотив: 662 (delete) и 663 (wait) уже были уязвимы в публичных цепочках
 * (Prolapse/Relapse); 664/665 - соседние недокументированные вызовы того же
 * семейства, принимающие userland-указатели. Проверяем, копирует ли ядро
 * userland-буферы с проверкой или доверяет указателю/индексу.
 * Ожидаемое поведение: EFAULT/EINVAL на битый указатель и на несуществующий id.
 * Детект: "VALIDATION-GAP" в /data/kexpl-t5-aio-poll.log, если ядро вернуло 0
 * (или код, отличный от EFAULT/EINVAL) на заведомо некорректный аргумент.
 */
#include "kexpl.h"

#define N 6
static u8  reqs[N][0x40];
static u32 ids[N];
static u32 states[N];
static u8  sink[0x40];

static int is_ok_errno(i64 rc, int *gap){
    if (rc == -EFAULT || rc == -EINVAL || rc == -EPERM) { *gap = 0; return 1; }
    *gap = 1; return 0;
}

int trig_main(void){
    zero_mem(ids, sizeof(ids));
    zero_mem(states, sizeof(states));
    zero_mem(sink, sizeof(sink));
    if (klog_init("t5-aio-poll", 1)) return 1;
    log_tag("t5"); log_s("AIO arg-validation probe (syscalls 663/664/665)\n");

    int sv[2] = {0,0};
    if (sys4(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, (i64)sv) != 0) {
        log_tag("t5"); log_s("RESULT: SKIP socketpair\n"); log_flush(1); return 0;
    }
    int n = 0;
    for (int i = 0; i < N; i++) {
        u8 *r = reqs[i];
        for (int j = 0; j < 0x40; j++) r[j] = 0;
        *(u32 *)(r + 0x08) = 1;
        *(u64 *)(r + 0x10) = (u64)sink;
        *(u32 *)(r + 0x20) = (u32)sv[0];
        u32 idout = 0;
        if (sys5(SYS_aio_submit_cmd, 1, (i64)r, 1, 3, (i64)&idout) == 0 && idout && idout < 0x100000)
            ids[n++] = idout;
    }
    log_tag("t5"); log_s("submitted="); log_l(n); log_s("\n");
    if (n == 0) { log_tag("t5"); log_s("RESULT: SKIP (нет AIO-запросов)\n"); sys1(SYS_close, sv[0]); log_flush(1); return 0; }

    int gaps = 0, gap = 0;
    long timeout[2]; timeout[0] = 5000; timeout[1] = 0;
    const i64 BADPTR = 0x0000dead0000LL;

    i64 r1 = sys3(SYS_aio_multi_poll, (i64)ids, n, (i64)states);
    log_tag("t5"); log_s("multi_poll(valid) rc="); log_l(r1); log_s("\n");

    i64 r2 = sys3(SYS_aio_multi_poll, (i64)ids, n, BADPTR);
    is_ok_errno(r2, &gap); if (gap) { gaps++; log_tag("t5"); log_s("VALIDATION-GAP: multi_poll(states=bad) rc="); log_l(r2); log_s("\n"); }
    else { log_tag("t5"); log_s("multi_poll(states=bad) отвергнут rc="); log_l(r2); log_s("\n"); }

    i64 r3 = sys3(SYS_aio_multi_poll, BADPTR, n, (i64)states);
    is_ok_errno(r3, &gap); if (gap) { gaps++; log_tag("t5"); log_s("VALIDATION-GAP: multi_poll(ids=bad) rc="); log_l(r3); log_s("\n"); }
    else { log_tag("t5"); log_s("multi_poll(ids=bad) отвергнут rc="); log_l(r3); log_s("\n"); }

    i64 r4 = sys2(SYS_aio_get_data, 0xdeadbeefLL, (i64)sink);
    is_ok_errno(r4, &gap); if (gap) { gaps++; log_tag("t5"); log_s("VALIDATION-GAP: get_data(bogus id) rc="); log_l(r4); log_s("\n"); }
    else { log_tag("t5"); log_s("get_data(bogus id) отвергнут rc="); log_l(r4); log_s("\n"); }

    i64 r5 = sys2(SYS_aio_get_data, (i64)ids[0], BADPTR);
    is_ok_errno(r5, &gap); if (gap) { gaps++; log_tag("t5"); log_s("VALIDATION-GAP: get_data(bad out) rc="); log_l(r5); log_s("\n"); }
    else { log_tag("t5"); log_s("get_data(bad out) отвергнут rc="); log_l(r5); log_s("\n"); }

    i64 r6 = sys5(SYS_aio_multi_wait, (i64)ids, n, BADPTR, 0, (i64)timeout);
    is_ok_errno(r6, &gap); if (gap) { gaps++; log_tag("t5"); log_s("VALIDATION-GAP: multi_wait(states=bad) rc="); log_l(r6); log_s("\n"); }
    else { log_tag("t5"); log_s("multi_wait(states=bad) отвергнут rc="); log_l(r6); log_s("\n"); }

    for (int i = 0; i < n; i++) { u32 one = ids[i]; sys3(SYS_aio_multi_cancel, (i64)&one, 1, (i64)states); }
    sys1(SYS_close, sv[0]); sys1(SYS_close, sv[1]);
    log_tag("t5"); log_s("gaps="); log_l(gaps); log_s("\n");
    if (gaps) { log_tag("t5"); log_s("RESULT: POSITIVE — найдены непроверяемые аргументы (кандидат на баг валидации)\n"); log_flush(1); return 2; }
    log_tag("t5"); log_s("RESULT: NEGATIVE — все битые аргументы отвергнуты\n");
    log_flush(1);
    return 0;
}
