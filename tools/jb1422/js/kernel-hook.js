/* jb1422 / kernel-hook.js — точка подключения kernel-стадии.
 *
 * Контракт с tools/jb1422/kernel/relapse1422.js (владелец: recon-fw-exists):
 *   export async function runKernelExploit(p, chain, log)
 *     p     — userland-примитив: p.read64/p.write64/p.read32/p.write32/p.add,
 *             p.ready()/p.reason(), typed: readDouble/writeDouble/readMatrix/writeMatrix.
 *     chain — объект syscalls (см. js/syscalls.js: syscall/mmap/malloc/mprotect/...).
 *     log   — function(text) для вывода в общий лог (STAGE-строки пишет сам модуль).
 *
 * Правила:
 *  - если модуль отсутствует на диске/не экспортирует runKernelExploit -> STAGE 11: BLOCKED
 *    с точным путём и ожидаемым экспортом (это интеграционная точка, не заглушка);
 *  - если p.ready() === false -> kernel-модуль всё равно вызывается: он должен сам
 *    напечатать, что ему нужно (обычно — leak/base), но мы логируем причину заранее;
 *  - никаких глобалов, только возвращаемый объект {status, detail, ...}.
 */
(function (global) {
  'use strict';

  var MODULE_PATH = './kernel/relapse1422.js';

  // kernel-модуль публикует себя как window.__jbKernelModule (контракт), но старые
  // сборки использовали window.Relapse1422 — принимаем оба, чтобы стык не рвался.
  function pickModule() {
    var a = global.__jbKernelModule, b = global.Relapse1422;
    if (a && typeof a.runKernelExploit === 'function') return a;
    if (b && typeof b.runKernelExploit === 'function') return b;
    return null;
  }

  function importModule(path) {
    // dynamic import поддерживается в Safari 17-эре (PS5), проверим наличие
    if (typeof global.__jbImport !== 'function') {
      // браузерный import() нельзя вызвать как строку в старых движках — используем
      // <script type="module"> инъекцию и ждём window.__jbKernelModule
      return null;
    }
    return global.__jbImport(path);
  }

  // Загрузка модуля через <script type="module"> (работает и в Safari 17.0-эре):
  //   kernel/relapse1422.js должен сделать:
  //     window.__jbKernelModule = { runKernelExploit, VERSION };
  function ensureKernelModuleLoaded(log) {
    return new Promise(function (resolve) {
      var pre = pickModule();
      if (pre) {
        return resolve({status: 'OK', module: pre, how: 'already-loaded'});
      }
      if (typeof global.document === 'undefined') {
        return resolve({status: 'BLOCKED', reason: 'no document (non-browser run)'});
      }
      var s = global.document.createElement('script');
      s.type = 'module';
      s.async = true;
      s.src = MODULE_PATH + '?t=' + Date.now();
      var done = false;
      function finish(r) { if (!done) { done = true; resolve(r); } }
      s.onload = function () {
        var mod = pickModule();
        if (mod) {
          finish({status: 'OK', module: mod, how: 'script-module'});
        } else {
          finish({status: 'BLOCKED',
            reason: MODULE_PATH + ' loaded but exposed neither window.__jbKernelModule nor window.Relapse1422 with runKernelExploit'});
        }
      };
      s.onerror = function () {
        finish({status: 'BLOCKED', reason: MODULE_PATH + ' not found (kernel stage not yet on disk)'});
      };
      (global.document.head || global.document.body).appendChild(s);
      // страховка: некоторые движки не вызывают onerror для module import
      global.setTimeout(function () {
        if (!done && !(global.__jbKernelModule && global.__jbKernelModule.runKernelExploit)) {
          finish({status: 'BLOCKED', reason: MODULE_PATH + ' did not load in 3s (module missing or blocked)'});
        }
      }, 3000);
    });
  }

  /**
   * STAGE 11: единая точка входа kernel-стадии.
   * Всегда возвращает объект со status: OK|FAIL|BLOCKED.
   */
  async function runKernelStage(p, config, log, chainOverride) {
    log = log || function () {};
    var loaded = await ensureKernelModuleLoaded(log);
    if (loaded.status !== 'OK') {
      return {
        status: 'BLOCKED',
        detail: loaded.reason + '; expected: ' + MODULE_PATH +
          ' → export function runKernelExploit(p, chain, log)',
        interface: {
          p: ['read64', 'write64', 'read32', 'write32', 'add', 'ready()', 'reason()'],
          chain: ['syscall', 'mmap', 'malloc', 'mprotect', 'resolve'],
          log: 'function(text)'
        },
        kernelOffsets: config ? config.kernelOffsets : null
      };
    }

    // chain: подключаем js/syscalls.js (если загружен) — он строит объект поверх p
    // chain приходит из stages.js (JB1422Bridge.createChain) — он уже с backend/queue;
    // fallback: старый JBSyscalls (если кто-то подключил его отдельно).
    var chain = chainOverride || null;
    if (!chain) {
      try {
        if (global.JBSyscalls && typeof global.JBSyscalls.createChain === 'function') {
          chain = global.JBSyscalls.createChain(p, log);
        }
      } catch (e) { log('chain create threw: ' + e); }
    }

    var primReady = !!(p && typeof p.ready === 'function' && p.ready());
    log('kernel stage: p.ready=' + primReady + ' reason=' + (p && p.reason ? p.reason() : 'n/a'));
    try {
      var mod = loaded.module;
      log('kernel stage: module VERSION=' + (mod.VERSION || 'unknown') + ' calling runKernelExploit(p, chain, log)');
      var res = await mod.runKernelExploit(p, chain, log);
      if (res === undefined) res = { status: 'FAIL', detail: 'kernel module returned undefined' };
      if (!res.status) res.status = 'FAIL';
      res.moduleHow = loaded.how;
      return res;
    } catch (e) {
      if (e && e.name === 'JbNotReady') {
        return { status: 'BLOCKED', detail: 'kernel module raised JbNotReady: ' + e.reason };
      }
      return { status: 'FAIL', detail: 'kernel module threw ' + ((e && e.name) || 'Error') + ': ' + ((e && e.message) || String(e)) };
    }
  }

  global.JBKernel = {
    MODULE_PATH: MODULE_PATH,
    runKernelStage: runKernelStage,
    ensureKernelModuleLoaded: ensureKernelModuleLoaded
  };
})(typeof window !== 'undefined' ? window : globalThis);