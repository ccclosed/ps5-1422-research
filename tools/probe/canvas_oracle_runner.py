#!/usr/bin/env python3
"""Run canvas_oracle.html inside the locally installed WebKitGTK (libwebkit2gtk-4.1).

The host has webkit2gtk4.1 2.52.5 (WebKit 7624-era, post-fix) and its
WebKitWebProcess, so the "fixed" branch of the oracle can be validated without
building anything.  The same HTML file is what you serve to the PS5 browser.

Usage: python3 canvas_oracle_runner.py [file-or-url]
"""
import json
import pathlib
import sys

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("WebKit2", "4.1")
from gi.repository import GLib, Gtk, WebKit2  # noqa: E402

TARGET = sys.argv[1] if len(sys.argv) > 1 else str(
    pathlib.Path(__file__).with_name("canvas_oracle.html")
)
if "://" not in TARGET:
    TARGET = pathlib.Path(TARGET).resolve().as_uri()

TIMEOUT_S = 25


class App(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="dev.ps5jb.canvasoracle")
        self.done = False

    def do_activate(self):
        win = Gtk.ApplicationWindow(application=self, title="oracle")
        win.set_default_size(400, 300)
        view = WebKit2.WebView()
        win.add(view)

        def finish(text, code=0):
            if self.done:
                return
            self.done = True
            print(text)
            self.quit()

        def on_js(view, result):
            try:
                value = view.run_javascript_finish(result).get_js_value().to_string()
            except Exception as exc:  # noqa: BLE001
                finish("RUNNER_ERROR js=" + repr(exc), 2)
                return
            finish(value)

        def on_load(view, event):
            if event == WebKit2.LoadEvent.FINISHED:
                view.run_javascript(
                    "document.getElementById('out').textContent", None, on_js
                )

        view.connect("load-changed", on_load)
        win.present()
        view.load_uri(TARGET)

        def bail():
            finish("TIMEOUT (web process may have crashed on the trigger)")
            return False

        GLib.timeout_add_seconds(TIMEOUT_S, bail)


if __name__ == "__main__":
    sys.exit(App().run([]))