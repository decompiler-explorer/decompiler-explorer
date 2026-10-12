"""Regression tests for resource-bounded decompiler subprocess execution."""

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from output_capture import OutputLimitExceeded, run_with_bounded_output


class OutputCaptureTests(unittest.TestCase):
    def run_python(self, script, *, input_bytes=b'', timeout=5, budget=1024):
        return run_with_bounded_output(
            [sys.executable, '-c', script], input_bytes=input_bytes,
            timeout=timeout, max_output_bytes=budget,
        )

    def test_round_trip_binary_stdin_and_stream_separation(self):
        result = self.run_python(
            'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read()); '
            'sys.stderr.buffer.write(b"warning")',
            input_bytes=b'\x00\xffhello',
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'\x00\xffhello')
        self.assertEqual(result.stderr, b'warning')

    def test_exact_limit_allowed(self):
        result = self.run_python('import os; os.write(1, b"x" * 1024)')
        self.assertEqual(len(result.stdout), 1024)

    def test_stdout_overflow_terminates_child(self):
        with self.assertRaises(OutputLimitExceeded):
            self.run_python('import os; os.write(1, b"x" * 65536)')

    def test_stderr_overflow_terminates_child(self):
        with self.assertRaises(OutputLimitExceeded):
            self.run_python('import os; os.write(2, b"y" * 65536)')

    def test_combined_budget(self):
        with self.assertRaises(OutputLimitExceeded):
            self.run_python('import os; os.write(1, b"x" * 600); os.write(2, b"y" * 600)')

    def test_timeout_terminates_process(self):
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            self.run_python('import time; time.sleep(20)', timeout=0.2)
        self.assertLess(time.monotonic() - started, 3)

    def test_nonzero_exit_preserves_diagnostic(self):
        result = self.run_python(
            'import os,sys; os.write(2,b"failed"); sys.exit(7)'
        )
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stderr, b'failed')

    def test_invalid_budget(self):
        with self.assertRaises(ValueError):
            self.run_python('pass', budget=0)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux process group behavior')
    def test_timeout_kills_descendants(self):
        with tempfile.TemporaryDirectory() as tmp:
            pid_file = os.path.join(tmp, 'grandchild.pid')
            code = (
                'import subprocess,sys,time; '
                'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"]); '
                f'open({pid_file!r},"w").write(str(p.pid)); '
                'time.sleep(30)'
            )
            with self.assertRaises(subprocess.TimeoutExpired):
                self.run_python(code, timeout=2.0)
            pid = int(Path(pid_file).read_text())
            # SIGKILL is asynchronous: poll until the grandchild is gone or a zombie.
            status = Path(f'/proc/{pid}/stat')
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                if not status.exists() or status.read_text().split(') ')[1][0] == 'Z':
                    break
                time.sleep(0.01)
            else:
                self.fail('Timed-out decompiler descendant was not terminated')


if __name__ == '__main__':
    unittest.main()
