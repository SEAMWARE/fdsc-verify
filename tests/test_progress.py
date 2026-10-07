"""The progress line must be informative, erasable, and never in the way.

The failure mode that matters is not "the spinner looks wrong": it is leftover
escape codes or a half-erased line ending up interleaved with the report, or -
worse - anything at all on stdout, which `--json | jq` has to keep parsing.
"""

import io
import unittest

from fdsc_verify.progress import Progress, null


class FakeStream(io.StringIO):
    def __init__(self, tty):
        io.StringIO.__init__(self)
        self._tty = tty

    def isatty(self):
        return self._tty


class TestProgress(unittest.TestCase):
    def test_disabled_writes_nothing(self):
        stream = FakeStream(tty=True)
        progress = Progress(stream=stream, enabled=False)
        progress.start("x")
        progress.detail("y")
        progress.note("z")
        progress.finish()
        progress.close()
        self.assertEqual(stream.getvalue(), "")

    def test_null_is_disabled(self):
        self.assertFalse(null().enabled)

    def test_non_tty_prints_plain_lines_only(self):
        stream = FakeStream(tty=False)
        progress = Progress(stream=stream, enabled=True)
        progress.start("[preflight 1/3] did-document")
        progress.detail("port-forward to identityhub-service")
        progress.finish()
        progress.close()
        output = stream.getvalue()
        self.assertEqual(output, "[preflight 1/3] did-document\n")
        self.assertNotIn("\r", output)
        self.assertNotIn("\033", output)

    def test_tty_repaints_and_erases(self):
        stream = FakeStream(tty=True)
        progress = Progress(stream=stream, enabled=True, tick=60)  # no ticker repaints
        progress.start("[preflight 1/3] did-document")
        progress.detail("port-forward to identityhub-service")
        progress.finish()
        output = stream.getvalue()
        self.assertIn("did-document", output)
        self.assertIn("port-forward to identityhub-service", output)
        self.assertTrue(output.startswith("\r"))
        # what is left on screen after the last carriage return is nothing
        self.assertEqual(output.rsplit("\r", 1)[1], "\033[K")
        progress.close()

    def test_note_survives_an_open_activity(self):
        """A permanent line must not be swallowed by the transient one."""
        stream = FakeStream(tty=True)
        progress = Progress(stream=stream, enabled=True, tick=60)
        progress.start("working")
        progress.note("  found: release consumer, lanes dcp, oid4vc")
        progress.close()
        self.assertIn("  found: release consumer, lanes dcp, oid4vc\n", stream.getvalue())

    def test_a_broken_stream_does_not_break_the_run(self):
        class Broken(FakeStream):
            def write(self, _):
                raise OSError("stderr closed")

        progress = Progress(stream=Broken(tty=True), enabled=True, tick=60)
        progress.start("working")       # must not raise
        progress.detail("still working")
        progress.close()
        self.assertFalse(progress.enabled)

    def test_bogus_terminal_width_does_not_eat_the_line(self):
        """`script`, pipes and detached sessions report widths of 0; do not believe them."""
        stream = FakeStream(tty=True)
        progress = Progress(stream=stream, enabled=True, tick=60)
        text = "[preflight 12/23] identity-key-consistency (oid4vc)"
        self.assertEqual(progress._fit(text), text)

    def test_close_is_idempotent(self):
        progress = Progress(stream=FakeStream(tty=True), enabled=True, tick=60)
        progress.start("working")
        progress.close()
        progress.close()


if __name__ == "__main__":
    unittest.main()
