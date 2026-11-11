#!/usr/bin/env python3
"""Run one entry-1422 probe page inside the locally installed WebKitGTK (WebKit2 4.1).

Purpose: validate that the probe pages work and what a post-fix WebKit (2.52.5) reports,
before carrying them to the console.  The console itself is reached through the
same local server (see run.sh / README.md); this runner is only a desktop smoke test.

Usage:
    python3 run_local.py p1-canvas-reentry.html
    python3 run_local.py p2-engine-fingerprint.html
    python3 run_local.py p3-crash-oracle.html '?armed=1'   # may kill the web process
"""
import json
import pathlib
import sys

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("WebKit2", "4.1")
from gi.repository import GLib, Gtk, WebKit2  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
PAGE = sys.argv[1] if len(sys.argv) > 1 else "p1-canvas-reentry.html"
QUERY = sys.argv[2] if len(sys.argv) > 2 else ""
TARGET = (HERE / PAGE).resolve().as_uri() + QUERY
TIMEOUT_S = 20


class App(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="dev.ps5jb.entry1422")
        self.done = False

    def finish(self, text, code=0):
        if not self.done:
            self.done = True
            print(text)
            self.quit()

    def do_activate(self):
        win = Gtk.ApplicationWindow(application=self, title="entry-1422 local")
        win.set_default_size(720, 480)
        view = WebKit2.WebView()
        win.add(view)

        def on_js(view, result):
            try:
                txt = view.run_javascript_finish(result).get_js_value().to_string()
            except Exception as exc:  # noqa: BLE001
                self.finish("LOCAL_RUNNER_ERROR " + repr(exc), 2)
                return
            try:
                parsed = json.loads(txt.split("=", 1)[1]) if "=" in txt else None
                print("LOCAL_PAGE_TITLE " + (view.get_title() or ""))
                print("LOCAL_PAGE_JSON " + json.dumps(parsed, ensure_ascii=False))
            except Exception:  # noqa: BLE001
                print("LOCAL_PAGE_TEXT " + txt)
            self.finish("LOCAL_DONE", 0)

        def on_load(view, event):
            if event == WebKit2.LoadEvent.FINISHED:
                view.run_javascript("document.getElementById('out').textContent", None, on_js)

        view.connect("load-changed", on_load)
        win.present()
        view.load_uri(TARGET)

        def bail():
            print("LOCAL_TIMEOUT (web process may have died on the trigger)")
            return False

        GLib.timeout_add_seconds(TIMEOUT_S, bail)


if __name__ == "__main__":
    sys.exit(App().run([]))