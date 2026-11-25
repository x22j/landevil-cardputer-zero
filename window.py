"""
window.py -- desktop window backend (uConsole, or any Linux desktop).

Drop-in for device.Framebuffer + device.Keyboard: the app still renders its
320x170 layout with Pillow (drawn at full resolution via ui.set_scale, 4x on
the uConsole's 1280x720 screen); this shows it in a Tk window and turns key presses into the
same Linux input keycodes the Cardputer keyboard produces, so App.on_key
doesn't know the difference.

Needs python3-tk and python3-pil.imagetk.
"""

import time
import tkinter as tk

from PIL import Image, ImageTk

from device import KEY

# Named keys by Tk keysym. Everything else (letters, digits, symbols) comes
# from the X keycode: on evdev-based X servers (Xorg, Xwayland) it is the
# Linux keycode + 8, which also keeps Shift handling identical to the device.
KEYSYMS = {
    "Escape": KEY["ESC"], "BackSpace": KEY["BACKSPACE"], "Tab": KEY["TAB"],
    "ISO_Left_Tab": KEY["TAB"], "Return": KEY["ENTER"], "KP_Enter": KEY["KPENTER"],
    "Shift_L": KEY["LEFTSHIFT"], "Shift_R": KEY["RIGHTSHIFT"],
    "Up": KEY["UP"], "Down": KEY["DOWN"], "Left": KEY["LEFT"], "Right": KEY["RIGHT"],
    "Prior": KEY["PAGEUP"], "Next": KEY["PAGEDOWN"], "Home": KEY["HOME"],
    "End": KEY["END"], "Delete": KEY["DELETE"], "space": KEY["SPACE"],
}
X_KEYCODE_OFFSET = 8
REPEAT_WINDOW = 0.03          # X autorepeat = release+press at the same instant


def linux_keycode(keysym, x_keycode):
    code = KEYSYMS.get(keysym)
    if code is not None:
        return code
    code = x_keycode - X_KEYCODE_OFFSET
    return code if 0 < code < 256 else None


class Window:
    """Shows frames and collects keys. Exposes the Framebuffer API (w, h,
    show, close) and the Keyboard API (poll, close) in one object, since
    both live in the same Tk window."""

    def __init__(self, w, h, fullscreen=True, scale=None, title="LAN Devil"):
        self.w, self.h = w, h
        self.closed = False
        self.root = tk.Tk(className="landevil")
        self.root.title(title)
        self.root.configure(bg="black")
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        fit = max(1, min(sw // w, sh // h))
        self.scale = scale or (fit if fullscreen else min(fit, 3))
        self.fullscreen = fullscreen
        self.label = tk.Label(self.root, bg="black", bd=0, highlightthickness=0)
        self.label.pack(expand=True, fill="both")
        if fullscreen:
            self.root.attributes("-fullscreen", True)
            self.root.configure(cursor="none")
        else:
            self.root.geometry(f"{w * self.scale}x{h * self.scale}")
            self.root.resizable(False, False)
        self.root.bind("<KeyPress>", self._on_press)
        self.root.bind("<KeyRelease>", self._on_release)
        self.root.bind("<F11>", lambda e: self._toggle_fullscreen())
        self.events = []
        self.pending_release = {}       # code -> monotonic time of release
        self.down = set()
        self._last = None
        self._photo = None
        self.root.update()
        self.root.focus_force()

    # ---- display --------------------------------------------------------

    def show(self, img):
        if self.closed:
            return
        img = img.convert("RGB")
        raw = img.tobytes()
        if raw == self._last:             # unchanged frame: skip the 4x upload
            self.root.update()
            return
        self._last = raw
        target = (self.w * self.scale, self.h * self.scale)
        if img.size != target:            # frames drawn at 1x (e.g. ui.SCALE not set)
            img = img.resize(target, Image.NEAREST)
        self._photo = ImageTk.PhotoImage(img)
        self.label.configure(image=self._photo)
        self.root.update()

    # ---- keyboard -------------------------------------------------------

    def _on_press(self, e):
        code = linux_keycode(e.keysym, e.keycode)
        if code is None:
            return
        if self.pending_release.pop(code, None) is not None or code in self.down:
            self.events.append((code, 2))       # autorepeat, like evdev value 2
        else:
            self.events.append((code, 1))
        self.down.add(code)

    def _on_release(self, e):
        code = linux_keycode(e.keysym, e.keycode)
        if code is not None:
            # Hold it back briefly: if a press follows at once it's autorepeat.
            self.pending_release[code] = time.monotonic()

    def _flush_releases(self, force=False):
        now = time.monotonic()
        for code, t in list(self.pending_release.items()):
            if force or now - t >= REPEAT_WINDOW:
                del self.pending_release[code]
                self.down.discard(code)
                self.events.append((code, 0))

    def poll(self, timeout):
        """Return (code, value) key events, waiting up to `timeout` seconds."""
        end = time.monotonic() + timeout
        while True:
            if self.closed:
                break
            try:
                self.root.update()
            except tk.TclError:
                self.closed = True
                break
            self._flush_releases()
            if self.events or time.monotonic() >= end:
                break
            time.sleep(0.01)
        out, self.events = self.events, []
        return out

    # ---- window ---------------------------------------------------------

    def _toggle_fullscreen(self):
        self.fullscreen = not self.fullscreen
        self.root.attributes("-fullscreen", self.fullscreen)
        self.root.configure(cursor="none" if self.fullscreen else "")

    def _on_close(self):
        self.closed = True

    def close(self):
        if self.root is None:
            return
        try:
            self.root.destroy()
        except tk.TclError:
            pass
        self.root = None
