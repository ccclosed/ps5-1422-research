/* ps5jb probe helpers - deliberately ES5 only.
 *
 * The PS5 browser engine is unknown to us, so the harness itself must not use a
 * syntax feature it is supposed to measure. Everything newer than ES5 is tested
 * through new Function()/eval in a try block and reported, never used directly.
 */
(function (global) {
  'use strict';

  var PS5JB = global.PS5JB || {};
  global.PS5JB = PS5JB;

  PS5JB.version = '1.0.0';
  PS5JB.beaconUrl = '/beacon';
  PS5JB.errors = [];
  PS5JB.startedAt = (new Date()).getTime();

  /* ------------------------------------------------------------------ util */
  var util = PS5JB.util = {};

  util.now = function () {
    if (global.performance && typeof global.performance.now === 'function') {
      return global.performance.now();
    }
    return (new Date()).getTime();
  };

  util.round = function (value, digits) {
    var factor = Math.pow(10, digits === undefined ? 2 : digits);
    return Math.round(value * factor) / factor;
  };

  util.ms = function (value) {
    return util.round(value, 1) + ' ms';
  };

  util.bytes = function (value) {
    var units = ['B', 'KiB', 'MiB', 'GiB'];
    var index = 0;
    while (value >= 1024 && index < units.length - 1) {
      value = value / 1024;
      index++;
    }
    return (index === 0 ? value : util.round(value, 1)) + ' ' + units[index];
  };

  /* Compile `src` as a function body: no execution, syntax check only. */
  util.syntaxOk = function (src) {
    try {
      /* eslint-disable no-new-func */
      new Function(src);
      return true;
    } catch (err) {
      return false;
    }
  };

  util.tryEval = function (src) {
    try {
      /* eslint-disable no-eval */
      return { ok: true, value: eval(src) };
    } catch (err) {
      return { ok: false, error: String(err && err.name ? err.name + ': ' + err.message : err) };
    }
  };

  util.hex = function (buffer) {
    var bytes = new Uint8Array(buffer);
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
      out += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return out;
  };

  util.query = function (name) {
    var match = new RegExp('[?&]' + name + '=([^&#]*)').exec(global.location.search || '');
    return match ? decodeURIComponent(match[1].replace(/\+/g, ' ')) : '';
  };

  /* -------------------------------------------------------------------- ui */
  var ui = PS5JB.ui = {};

  ui.h = function (tag, className, text) {
    var node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (text !== undefined && text !== null) {
      node.textContent = String(text);
    }
    return node;
  };

  ui.section = function (title, description) {
    var section = ui.h('section', 'card');
    section.appendChild(ui.h('h2', null, title));
    if (description) {
      section.appendChild(ui.h('p', 'muted', description));
    }
    document.getElementById('main').appendChild(section);
    return section;
  };

  ui.table = function (parent, headers) {
    var table = ui.h('table', 'results');
    var head = ui.h('thead');
    var row = ui.h('tr');
    for (var i = 0; i < headers.length; i++) {
      row.appendChild(ui.h('th', null, headers[i]));
    }
    head.appendChild(row);
    table.appendChild(head);
    var body = ui.h('tbody');
    table.appendChild(body);
    parent.appendChild(table);
    return body;
  };

  ui.row = function (body, status, name, value) {
    var row = ui.h('tr');
    var statusCell = ui.h('td', 'status status-' + status, status);
    var nameCell = ui.h('td', 'name', name);
    var valueCell = ui.h('td', 'value');
    if (value && typeof value === 'object' && value.nodeType) {
      valueCell.appendChild(value);
    } else {
      valueCell.textContent = value === undefined || value === null ? '' : String(value);
    }
    row.appendChild(statusCell);
    row.appendChild(nameCell);
    row.appendChild(valueCell);
    body.appendChild(row);
    return row;
  };

  ui.badge = function (kind, text) {
    return ui.h('span', 'badge badge-' + kind, text);
  };

  ui.note = function (parent, text) {
    var note = ui.h('p', 'note', text);
    parent.appendChild(note);
    return note;
  };

  /* ----------------------------------------------------------------- report */
  var report = PS5JB.report = {};

  report.envelope = function (probe, results, extra) {
    var agent = global.navigator || {};
    var screenInfo = global.screen || {};
    var envelope = {
      version: PS5JB.version,
      probe: probe,
      page: (global.location && global.location.pathname) || '',
      href: (global.location && global.location.href) || '',
      ts: (new Date()).toISOString(),
      ua: agent.userAgent || '',
      language: agent.language || '',
      platform: agent.platform || '',
      screen: (screenInfo.width || 0) + 'x' + (screenInfo.height || 0) +
        '@' + (global.devicePixelRatio || 1),
      visibility: (global.document && document.visibilityState) || '',
      elapsed_ms: util.round(util.now() - PS5JB.startedAt, 1),
      results: results,
      errors: PS5JB.errors.slice(0)
    };
    if (extra) {
      for (var key in extra) {
        if (Object.prototype.hasOwnProperty.call(extra, key)) {
          envelope[key] = extra[key];
        }
      }
    }
    return envelope;
  };

  function postJson(payload, callback) {
    var body = JSON.stringify(payload);
    var done = false;

    function finish(status, text) {
      if (done) {
        return;
      }
      done = true;
      if (callback) {
        callback(status, text);
      }
    }

    if (global.XMLHttpRequest) {
      try {
        var xhr = new global.XMLHttpRequest();
        xhr.open('POST', PS5JB.beaconUrl, true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.onreadystatechange = function () {
          if (xhr.readyState === 4) {
            finish(xhr.status, xhr.responseText || '');
          }
        };
        xhr.send(body);
        return;
      } catch (err) {
        PS5JB.errors.push('xhr: ' + err);
      }
    }
    if (agent_sendBeacon()) {
      var sent = global.navigator.sendBeacon(
        PS5JB.beaconUrl,
        new global.Blob([body], { type: 'text/plain;charset=UTF-8' })
      );
      finish(sent ? 0 : -1, 'sendBeacon');
      return;
    }
    finish(-1, 'no transport');
  }

  function agent_sendBeacon() {
    return !!(global.navigator && typeof global.navigator.sendBeacon === 'function' && global.Blob);
  }

  report.send = function (probe, results, extra, callback) {
    postJson(report.envelope(probe, results, extra), callback);
  };

  /* Collect marks on a page, then send once. */
  PS5JB.results = {};
  PS5JB.mark = function (key, value) {
    PS5JB.results[key] = value;
    return value;
  };
  PS5JB.send = function (probe, extra, callback) {
    report.send(probe, PS5JB.results, extra, callback);
  };

  /* ------------------------------------------------------------------- dom */
  PS5JB.status = function (text) {
    var node = document.getElementById('status');
    if (node) {
      node.textContent = text;
      node.className = 'statusline';
    }
  };

  PS5JB.button = function (label, handler) {
    var button = ui.h('button', 'action', label);
    button.type = 'button';
    button.onclick = handler;
    return button;
  };

  PS5JB.onerror = function (message, source, line, column, error) {
    PS5JB.errors.push(message + ' @' + (source || '?') + ':' + line + ':' + column +
      (error && error.stack ? ' | ' + error.stack : ''));
    PS5JB.status('JS error: ' + message);
    return false;
  };
  global.onerror = PS5JB.onerror;

  if (global.addEventListener) {
    global.addEventListener('unhandledrejection', function (event) {
      PS5JB.errors.push('unhandledrejection: ' + event.reason);
    }, false);
  }

  /* Report that a page was opened even if its own logic dies later. */
  PS5JB.opened = function (probe) {
    report.send(probe, { event: 'page-opened' });
  };

  /* ------------------------------------------------------- engine detection */
  PS5JB.env = function () {
    var nav = global.navigator || {};
    var env = {
      userAgent: nav.userAgent || '',
      appVersion: nav.appVersion || '',
      vendor: nav.vendor || '',
      platform: nav.platform || '',
      languages: nav.languages || (nav.language ? [nav.language] : []),
      hardwareConcurrency: nav.hardwareConcurrency || null,
      deviceMemory: nav.deviceMemory || null,
      maxTouchPoints: nav.maxTouchPoints || 0,
      onLine: nav.onLine,
      cookieEnabled: nav.cookieEnabled,
      javaEnabled: typeof nav.javaEnabled === 'function' ? nav.javaEnabled() : null,
      webdriver: nav.webdriver === true,
      plugins: nav.plugins ? nav.plugins.length : null,
      mimeTypes: nav.mimeTypes ? nav.mimeTypes.length : null
    };
    if (global.screen) {
      env.screen = {
        width: screen.width,
        height: screen.height,
        availWidth: screen.availWidth,
        availHeight: screen.availHeight,
        colorDepth: screen.colorDepth,
        pixelDepth: screen.pixelDepth,
        devicePixelRatio: global.devicePixelRatio || 1
      };
    }
    if (global.performance && global.performance.memory) {
      env.heap = {
        jsHeapSizeLimit: performance.memory.jsHeapSizeLimit || null,
        totalJSHeapSize: performance.memory.totalJSHeapSize || null,
        usedJSHeapSize: performance.memory.usedJSHeapSize || null
      };
    }
    if (global.performance && typeof performance.timeOrigin === 'number') {
      env.timeOrigin = performance.timeOrigin;
    }
    env.webkit = null;
    if (global.webkit && typeof global.webkit === 'object') {
      env.webkit = {
        hasTouchIcon: 'touchIconURL' in global.webkit,
        hasMessageHandlers: typeof global.webkit.messageHandlers === 'object',
        hasMediaDevice: typeof global.webkitGetUserMedia === 'function'
      };
    }
    return env;
  };

  PS5JB.features = function () {
    var features = {};
    var checks = {
      JSON: 'typeof JSON !== "undefined"',
      Promise: 'typeof Promise === "function"',
      Symbol: 'typeof Symbol === "function"',
      Proxy: 'typeof Proxy === "function"',
      Reflect: 'typeof Reflect === "object"',
      Map: 'typeof Map === "function"',
      Set: 'typeof Set === "function"',
      WeakMap: 'typeof WeakMap === "function"',
      BigInt: 'typeof BigInt === "function"',
      ArrayBuffer: 'typeof ArrayBuffer === "function"',
      SharedArrayBuffer: 'typeof SharedArrayBuffer === "function"',
      Atomics: 'typeof Atomics === "object"',
      DataView: 'typeof DataView === "function"',
      WebAssembly: 'typeof WebAssembly === "object"',
      WebGL: 'typeof WebGLRenderingContext === "function"',
      WebGL2: 'typeof WebGL2RenderingContext === "function"',
      WebSocket: 'typeof WebSocket === "function"',
      Worker: 'typeof Worker === "function"',
      Blob: 'typeof Blob === "function"',
      FileReader: 'typeof FileReader === "function"',
      IndexedDB: 'typeof indexedDB === "object"',
      WebRTC: 'typeof RTCPeerConnection === "function"',
      AudioContext: 'typeof AudioContext === "function" || typeof webkitAudioContext === "function"',
      WebAudio: 'typeof AudioContext === "function"',
      PointerEvent: 'typeof PointerEvent === "function"',
      TouchEvent: 'typeof TouchEvent === "function"',
      GamepadEvent: 'typeof GamepadEvent === "function"',
      MutationObserver: 'typeof MutationObserver === "function"',
      IntersectionObserver: 'typeof IntersectionObserver === "function"',
      CropAndResize: 'typeof ImageCapture === "function"',
      CSSSupports: 'typeof CSS !== "undefined" && typeof CSS.supports === "function"',
      DeviceOrientation: 'typeof DeviceOrientationEvent === "function"',
      Battery: 'typeof navigator.getBattery === "function"',
      ServiceWorker: 'typeof navigator.serviceWorker === "object"',
      PushManager: 'typeof PushManager === "function"',
      MediaSource: 'typeof MediaSource === "function"',
      MSEH264: 'typeof MediaSource !== "undefined" && MediaSource.isTypeSupported && MediaSource.isTypeSupported("video/mp4; codecs=\\"avc1.42E01E\\"")',
      MSEHEVC: 'typeof MediaSource !== "undefined" && MediaSource.isTypeSupported && MediaSource.isTypeSupported("video/mp4; codecs=\\"hvc1.1.6.L93.B0\\"")',
      WebGPU: 'typeof navigator.gpu === "object"'
    };
    for (var name in checks) {
      if (Object.prototype.hasOwnProperty.call(checks, name)) {
        var result = util.tryEval(checks[name]);
        features[name] = result.ok ? !!result.value : 'error: ' + result.error;
      }
    }
    features.syntax = {
      'let/const': util.syntaxOk('let a = 1; const b = 2;'),
      'arrow': util.syntaxOk('var f = (a) => a + 1;'),
      'template literal': util.syntaxOk('var s = `x${1}`;'),
      'class': util.syntaxOk('class A { constructor() { this.x = 1; } }'),
      'destructuring': util.syntaxOk('var [a, b] = [1, 2];'),
      'spread': util.syntaxOk('var a = [1]; var b = [0, ...a];'),
      'default params': util.syntaxOk('function f(a = 1) { return a; }'),
      'for-of': util.syntaxOk('for (var x of [1]) { x; }'),
      'generator': util.syntaxOk('function* g() { yield 1; }'),
      'async/await': util.syntaxOk('async function f() { await 0; }'),
      'optional chaining': util.syntaxOk('var a = {}; var b = a?.b;'),
      'nullish coalescing': util.syntaxOk('var a = null ?? 1;'),
      'object spread': util.syntaxOk('var a = { ...{ x: 1 } };'),
      'BigInt literal': util.syntaxOk('var a = 1n;')
    };
    return features;
  };

  PS5JB.engineGuess = function () {
    var ua = (global.navigator && navigator.userAgent) || '';
    var guess = { family: 'unknown', version: null, guess: '' };
    var match = /AppleWebKit\/([0-9.]+)/.exec(ua);
    if (match) {
      guess.family = 'WebKit';
      guess.version = match[1];
      guess.guess = 'WebKit ' + match[1];
    }
    if (/Chrome\/([0-9.]+)/.test(ua)) {
      guess.family = 'Blink (Chrome-like)';
      guess.version = RegExp.$1;
      guess.guess = 'Blink ' + RegExp.$1;
    }
    if (/Gecko\/|Firefox\//.test(ua)) {
      guess.family = 'Gecko';
    }
    if (/PlayStation/.test(ua)) {
      guess.guess += ' [PlayStation UA]';
    }
    return guess;
  };

  /* Non-throwing WebGL renderer string, useful to identify the GPU/driver. */
  PS5JB.webglInfo = function () {
    var info = { available: false };
    try {
      var canvas = document.createElement('canvas');
      var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) {
        return info;
      }
      info.available = true;
      info.version = gl.getParameter(gl.VERSION);
      info.vendor = gl.getParameter(gl.VENDOR);
      info.renderer = gl.getParameter(gl.RENDERER);
      info.shading = gl.getParameter(gl.SHADING_LANGUAGE_VERSION);
      var debug = gl.getExtension('WEBGL_debug_renderer_info');
      if (debug) {
        info.unmaskedVendor = gl.getParameter(debug.UNMASKED_VENDOR_WEBGL);
        info.unmaskedRenderer = gl.getParameter(debug.UNMASKED_RENDERER_WEBGL);
      }
      info.maxTexture = gl.getParameter(gl.MAX_TEXTURE_SIZE);
      info.maxRenderbuffer = gl.getParameter(gl.MAX_RENDERBUFFER_SIZE);
      info.maxViewport = gl.getParameter(gl.MAX_VIEWPORT_DIMS);
    } catch (err) {
      info.error = String(err);
    }
    return info;
  };

  /* --------------------------------------------------------------- helpers */
  PS5JB.sleep = function (ms, callback) {
    global.setTimeout(callback, ms || 0);
  };

  PS5JB.sequence = function (steps, done) {
    var index = 0;
    function next() {
      if (index >= steps.length) {
        if (done) {
          done();
        }
        return;
      }
      var step = steps[index++];
      global.setTimeout(function () {
        try {
          step(next);
        } catch (err) {
          PS5JB.errors.push('sequence: ' + err);
          next();
        }
      }, 0);
    }
    next();
  };

  /* ------------------------------------------------------------ page chrome */
  PS5JB.initPage = function (title, subtitle) {
    var header = ui.h('header', 'pagehead');
    header.appendChild(ui.h('h1', null, title));
    if (subtitle) {
      header.appendChild(ui.h('p', 'muted', subtitle));
    }
    var status = ui.h('div', 'statusline', 'загрузка…');
    status.id = 'status';
    header.appendChild(status);
    document.body.appendChild(header);
    var main = ui.h('main');
    main.id = 'main';
    document.body.appendChild(main);
    var footer = ui.h('footer', 'pagefoot');
    footer.appendChild(ui.h('span', null, 'ps5jb probe ' + PS5JB.version + ' — ' +
      (global.location && location.pathname)));
    var nav = ui.h('a', 'navlink', '← все пробы');
    nav.href = '/';
    footer.appendChild(nav);
    document.body.appendChild(footer);
    return main;
  };
}(this));