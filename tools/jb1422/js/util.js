/* jb1422 / util.js — логирование, beacons, конверсии, окружение.
 *
 * Никаких зависимостей. Подключается первым (<script src="js/util.js">).
 * Каждый лог-лайн формата:
 *   [t] STAGE n: OK|FAIL|BLOCKED — текст {json}
 * одновременно уходит на /beacon (если сервер стенда поднят) и в <pre id="jb-log">.
 */
(function (global) {
  'use strict';

  var LOG_ID = 'jb-log';
  var MAX_LINES = 4000;
  var beaconSeq = 0;

  function now() {
    try { return (new Date()).toISOString().slice(11, 23); } catch (e) { return '--:--:--'; }
  }

  function el() {
    if (!global.document) return null;
    return global.document.getElementById(LOG_ID);
  }

  // Сырые значения: числа, строки, address-строки, объекты — печатаем стабильно.
  function fmt(v) {
    if (v === null) return 'null';
    if (v === undefined) return 'undefined';
    if (typeof v === 'number') {
      if (v !== v) return 'NaN';
      if (!isFinite(v)) return String(v);
      // адреса передаём строками '0x...'; числа печатаем как есть + hex-хвост для целых
      if (Math.floor(v) === v && Math.abs(v) >= 0x1000) return v + '(0x' + v.toString(16) + ')';
      return String(v);
    }
    if (typeof v === 'string') return v;
    try { return JSON.stringify(v); } catch (e) { return String(v); }
  }

  function log(line) {
    var text = '[' + now() + '] ' + line;
    var pre = el();
    if (pre) {
      pre.textContent += text + '\n';
      var lines = pre.textContent.split('\n');
      if (lines.length > MAX_LINES) pre.textContent = lines.slice(-MAX_LINES).join('\n');
      pre.scrollTop = pre.scrollHeight;
    }
    // console для devtools/локального прогона
    try { if (global.console && console.log) console.log(text); } catch (e) {}
    return text;
  }

  function beacon(tag, payload) {
    if (!global.location || !/^https?:$/.test(global.location.protocol || '')) return 'no-origin';
    var body;
    try { body = JSON.stringify({ tag: tag, seq: ++beaconSeq, payload: payload }); }
    catch (e) { body = JSON.stringify({ tag: tag, seq: ++beaconSeq, payload: String(payload) }); }
    try {
      if (typeof global.fetch === 'function') {
        global.fetch('/beacon', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body });
        return 'fetch';
      }
    } catch (e) {}
    try {
      var x = new global.XMLHttpRequest();
      x.open('POST', '/beacon', true);
      x.setRequestHeader('Content-Type', 'application/json');
      x.send(body);
      return 'xhr';
    } catch (e) { return 'none'; }
  }

  // STAGE n: OK/FAIL/BLOCKED — единая точка вывода стадии.
  function stage(n, status, text, data) {
    var head = 'STAGE ' + n + ': ' + status + ' — ' + text;
    var detail = '';
    if (data !== undefined) {
      try { detail = ' ' + JSON.stringify(data, function (k, v) {
        if (typeof v === 'number' && !isFinite(v)) return String(v);
        return v;
      }); } catch (e) { detail = ' ' + String(data); }
    }
    log(head + detail);
    beacon('STAGE-' + n, { status: status, text: text, data: data });
    return { stage: n, status: status, text: text, data: data };
  }

  // ---- конверсии double <-> биты (без арифметики над значением) ----
  var f64buf = new ArrayBuffer(8);
  var f64 = new Float64Array(f64buf);
  var u32 = new Uint32Array(f64buf);
  var u8 = new Uint8Array(f64buf);

  function f64hex(x) {
    f64[0] = x;
    var hi = u32[1].toString(16), lo = u32[0].toString(16);
    while (hi.length < 8) hi = '0' + hi;
    while (lo.length < 8) lo = '0' + lo;
    return hi + lo; // big-endian hex of the 64-bit pattern
  }

  function f64bytes(x) {
    f64[0] = x;
    return [u8[0], u8[1], u8[2], u8[3], u8[4], u8[5], u8[6], u8[7]];
  }

  function bytesToF64(arr, off) {
    for (var i = 0; i < 8; i++) u8[i] = arr[(off || 0) + i];
    return f64[0];
  }

  function close(a, b, eps) {
    eps = eps === undefined ? 1e-9 : eps;
    if (a === b) return true;
    if (typeof a !== 'number' || typeof b !== 'number') return false;
    if (!isFinite(a) || !isFinite(b)) return false;
    return Math.abs(a - b) <= eps * Math.max(1, Math.abs(a), Math.abs(b));
  }

  // строковые адреса: addStr('0x1000', 0x20) -> '0x1020'
  function addStr(addr, off) {
    var a = String(addr);
    if (!/^0x[0-9a-fA-F]+$/.test(a)) throw new Error('addStr: bad address ' + a);
    var n = parseInt(a, 16);
    if (!isFinite(n)) throw new Error('addStr: address overflow ' + a);
    return '0x' + (n + (off || 0)).toString(16);
  }

  function u64hex(lo, hi) { // little-endian pair (lo, hi) -> 0xhi_lo
    function p(x) { var s = (x >>> 0).toString(16); while (s.length < 8) s = '0' + s; return s; }
    return '0x' + p(hi) + p(lo);
  }

  function hex(n, width) {
    var s = (n >>> 0).toString(16);
    while (s.length < (width || 8)) s = '0' + s;
    return s;
  }

  function env() {
    var n = global.navigator || {};
    var ua = n.userAgent || 'unknown';
    var fw = 'unknown';
    var m = /PlayStation 5\/([0-9.]+)/.exec(ua);
    if (m) fw = m[1];
    var feats = {};
    var checks = {
      canvas2d: function () { return !!global.document.createElement('canvas').getContext('2d'); },
      bitmaprenderer: function () { return typeof global.ImageBitmapRenderingContext !== 'undefined'; },
      offscreen: function () { return typeof global.OffscreenCanvas !== 'undefined'; },
      wasm: function () { return typeof global.WebAssembly !== 'undefined'; },
      sab: function () { return typeof global.SharedArrayBuffer !== 'undefined'; },
      biguint64: function () { return typeof global.BigUint64Array !== 'undefined'; },
      atomics: function () { return typeof global.Atomics !== 'undefined'; },
      workers: function () { return typeof global.Worker !== 'undefined'; },
      fontface: function () { return typeof global.FontFace !== 'undefined'; },
      structuredClone: function () { return typeof global.structuredClone === 'function'; },
      rab: function () { try { return typeof global.ArrayBuffer.prototype.resize === 'function'; } catch (e) { return false; } }
    };
    Object.keys(checks).forEach(function (k) {
      try { feats[k] = checks[k](); } catch (e) { feats[k] = 'throw'; }
    });
    return {
      userAgent: ua,
      firmware: fw,
      isPS5: /PlayStation 5/.test(ua),
      hardwareConcurrency: n.hardwareConcurrency || 0,
      secureContext: (typeof global.isSecureContext === 'boolean') ? global.isSecureContext : null,
      location: String(global.location && global.location.href || ''),
      features: feats
    };
  }

  function sleep(ms) {
    return new Promise(function (resolve) { setTimeout(resolve, ms); });
  }

  global.JBUtil = {
    LOG_ID: LOG_ID,
    log: log,
    stage: stage,
    beacon: beacon,
    fmt: fmt,
    f64hex: f64hex,
    f64bytes: f64bytes,
    bytesToF64: bytesToF64,
    close: close,
    u64hex: u64hex,
    addStr: addStr,
    hex: hex,
    env: env,
    sleep: sleep
  };
})(typeof window !== 'undefined' ? window : globalThis);