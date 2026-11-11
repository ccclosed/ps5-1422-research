#!/usr/bin/env python3
"""Run tools/jb1422/index.html in the locally installed WebKitGTK and dump the jb-log text.

This is the PC-side smoke test: the local WebKitGTK 2.52.5 is post-fix (CVE-2026-43720),
so the expected honest result is:
  STAGE 0 OK, STAGE 1 OK, STAGE H OK (harness 12/12), STAGE 2 FAIL (engine fixed),
  STAGE 3-7 BLOCKED, STAGE 8 OK, STAGE 9-12 BLOCKED, SUMMARY FAIL with PC explanation.

Usage: python3 tools/jb1422/tests/run_local_webkit.py [--run|--harness] [--out FILE]
"""
import argparse
import functools
import http.server
import pathlib
import socketserver
import sys
import threading

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("WebKit2", "4.1")
from gi.repository import GLib, Gtk, WebKit2  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
ROOT = (HERE.parent).resolve()
INDEX = ROOT / "index.html"
TIMEOUT_S = 30


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):  # noqa: D401 - тишина в выводе
        pass


def serve(root: pathlib.Path):
    """file:// запрещает <script type="module">; поднимаем локальный HTTP."""
    handler = functools.partial(_Quiet, directory=str(root))
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, port


class App(Gtk.Application):
    def __init__(self, mode, out_path):
        super().__init__(application_id="dev.ps5jb.jb1422")
        self.mode = mode
        self.out_path = out_path
        self.done = False

    def finish(self, text, code=0):
        if self.done:
            return
        self.done = True
        print(text)
        if self.out_path:
            pathlib.Path(self.out_path).write_text(text + "\n")
        self.quit()

    def do_activate(self):
        win = Gtk.ApplicationWindow(application=self, title="jb1422 local")
        win.set_default_size(900, 700)
        view = WebKit2.WebView()
        win.add(view)

        def grab():
            view.run_javascript(
                "document.getElementById('jb-log').textContent", None, on_js
            )
            return False

        def on_js(view_, result, *_):
            try:
                js = view_.run_javascript_finish(result)
                text = js.get_js_value().to_string()
            except Exception as exc:  # noqa: BLE001
                self.finish("LOCAL_RUNNER_ERROR " + repr(exc), 2)
                return
            self.finish(text or "(empty log)")

        def on_load(view_, event):
            if event != WebKit2.LoadEvent.FINISHED:
                return
            if self.mode == "harness":
                view_.run_javascript(
                    "document.getElementById('btn-harness').click()", None, None
                )
            else:
                view_.run_javascript(
                    "document.getElementById('btn-run').click()", None, None
                )
            # даём стадиям доработать (kernel-hook ждёт 3с таймаут при отсутствии модуля)
            GLib.timeout_add_seconds(1, grab)

        view.connect("load-changed", on_load)
        win.present()
        httpd, port = serve(ROOT)
        view.load_uri(f"http://127.0.0.1:{port}/index.html")

        def bail():
            self.finish("LOCAL_TIMEOUT (web process may have died)")
            return False

        GLib.timeout_add_seconds(TIMEOUT_S, bail)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", action="store_true", default=True)
    ap.add_argument("--harness", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()
    mode = "harness" if args.harness else "run"
    return App(mode, args.out).run([])


if __name__ == "__main__":
    sys.exit(main())