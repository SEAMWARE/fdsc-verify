"""Say what is happening while it happens.

A full run takes minutes: discovery shells out to kubectl half a dozen times, and
several checks open a port-forward, exec into a pod or poll a negotiation until it
times out. The report is only printed at the end, so without this the tool looks
hung for the first minute — which is exactly when an operator kills it and assumes
their kubeconfig is wrong.

Two rules:

- **stderr, never stdout.** stdout carries the report, and `--json | jq` has to keep
  working. Progress is for the human watching, so it goes where the human is.
- **The transient line leaves nothing behind.** On a TTY the current activity is
  repainted in place and erased when the run ends, so what remains on screen is the
  report and nothing else. Off a TTY (CI, `2>log`) there is nothing to repaint, so
  each activity prints one plain line as it starts and no cursor codes are emitted.

The ticker thread exists because the elapsed counter is the whole point: a frozen
`kubectl port-forward` and a slow one look identical without it.
"""

from __future__ import annotations

import os
import shutil
import sys
import threading
import time
from typing import Optional

_SPINNER = "|/-\\"
_CLEAR_LINE = "\033[K"
# below this, the seconds counter is just noise; above it, it is the reassurance
_SHOW_ELAPSED_AFTER = 2.0
# a reported width under this is not a terminal telling the truth
_MIN_WIDTH = 30


class Progress:
    """Single-activity progress on stderr. Disabled instances are no-ops."""

    def __init__(self, stream=None, enabled: bool = True, tick: float = 0.4):
        self.stream = stream if stream is not None else sys.stderr
        self.enabled = enabled
        self.tty = enabled and bool(getattr(self.stream, "isatty", lambda: False)())
        self._tick = tick
        self._lock = threading.RLock()
        self._label: Optional[str] = None
        self._detail: Optional[str] = None
        self._started = 0.0
        self._frame = 0
        self._dirty = False          # something is painted on the current line
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # --------------------------------------------------------------- public API

    def start(self, label: str, detail: str = "") -> None:
        """Begin an activity, replacing whatever was running before."""
        if not self.enabled:
            return
        with self._lock:
            self._label, self._detail = label, detail or None
            self._started = time.monotonic()
            self._frame = 0
            if self.tty:
                self._paint()
                self._ensure_ticker()
            else:
                self._writeline(label + (" - %s" % detail if detail else ""))

    def detail(self, text: str) -> None:
        """Refine the current activity: which port-forward, which poll, which pod.

        Silent off a TTY: one line per check is liveness, one line per sub-step is
        a log flood.
        """
        if not self.enabled or self._label is None:
            return
        with self._lock:
            self._detail = text or None
            if self.tty:
                self._paint()

    def finish(self) -> None:
        """End the current activity.

        Deliberately says nothing about the outcome: the report carries the status
        a few seconds later, and printing it twice trains the operator to read the
        transient copy, which is the one that scrolls away.
        """
        if not self.enabled or self._label is None:
            return
        with self._lock:
            self._label = self._detail = None
            self._erase()

    def note(self, text: str) -> None:
        """A line that stays: what discovery found, how long the run took."""
        if not self.enabled:
            return
        with self._lock:
            self._erase()
            self._writeline(text)
            if self.tty and self._label:
                self._paint()

    def close(self) -> None:
        """Stop the ticker and leave the cursor on a clean line."""
        if not self.enabled:
            return
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=1.0)
            self._thread = None
        with self._lock:
            self._label = self._detail = None
            self._erase()

    def __enter__(self) -> "Progress":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------ painting

    def _ensure_ticker(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run_ticker, name="fdsc-progress",
                                        daemon=True)
        self._thread.start()

    def _run_ticker(self) -> None:
        while not self._stop.wait(self._tick):
            with self._lock:
                if self._label is not None:
                    self._frame += 1
                    self._paint()

    def _paint(self) -> None:
        """Repaint the transient line. Caller holds the lock; TTY only."""
        text = "%s %s" % (_SPINNER[self._frame % len(_SPINNER)], self._label)
        if self._detail:
            text += " - %s" % self._detail
        elapsed = time.monotonic() - self._started
        if elapsed >= _SHOW_ELAPSED_AFTER:
            text += "  %ds" % int(elapsed)
        self._write("\r%s%s" % (self._fit(text), _CLEAR_LINE))
        self._dirty = True

    def _fit(self, text: str) -> str:
        """Truncate to the terminal width so a long detail does not wrap.

        A wrapped transient line cannot be erased - `\\r` only reaches the start of
        the last row - so the leftovers would end up interleaved with the report.
        Widths below _MIN_WIDTH are not believed: `script`, a pipe and a detached
        session all report nonsense here, and truncating to that would leave every
        line an ellipsis.
        """
        width = 0
        try:
            width = os.get_terminal_size(self.stream.fileno()).columns
        except (OSError, ValueError, AttributeError):
            width = shutil.get_terminal_size((0, 0)).columns
        if width < _MIN_WIDTH or len(text) < width:
            return text
        return text[:width - 2] + "…"

    def _erase(self) -> None:
        if self._dirty and self.tty:
            self._write("\r%s" % _CLEAR_LINE)
        self._dirty = False

    def _writeline(self, text: str) -> None:
        self._write("%s\n" % text)
        self._dirty = False

    def _write(self, text: str) -> None:
        # Progress must never be the reason a run dies: a closed stderr, a broken
        # pipe or a stream that cannot encode the frame is not worth an exception.
        try:
            self.stream.write(text)
            self.stream.flush()
        except (OSError, ValueError, UnicodeError):
            self.enabled = self.tty = False


def null() -> Progress:
    """A Progress that does nothing, for --quiet and for callers with no stream."""
    return Progress(enabled=False)
