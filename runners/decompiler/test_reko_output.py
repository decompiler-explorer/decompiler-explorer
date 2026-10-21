"""Regression tests for the Reko adapter's streaming diagnostics/output."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from output_capture import OutputLimitExceeded, run_with_bounded_output

REKO_ADAPTER = Path(__file__).with_name('decompile_reko.py')


class RekoOutputTests(unittest.TestCase):
    def run_fake_reko(self, fake_code, *, limit=1024 * 1024):
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            fake_reko = directory / 'reko'
            fake_reko.write_text('#!/usr/bin/env python3\n' + fake_code)
            fake_reko.chmod(0o755)
            # output_capture inherits environment; scope this modification to the test.
            previous = os.environ.get('REKO_INSTALL_PATH')
            try:
                os.environ['REKO_INSTALL_PATH'] = d
                return run_with_bounded_output(
                    [sys.executable, str(REKO_ADAPTER)], input_bytes=b'ELF',
                    cwd=d, timeout=10, max_output_bytes=limit,
                )
            finally:
                if previous is None:
                    os.environ.pop('REKO_INSTALL_PATH', None)
                else:
                    os.environ['REKO_INSTALL_PATH'] = previous

    def test_diagnostics_do_not_corrupt_decompiled_source(self):
        result = self.run_fake_reko(
            'import os,sys,pathlib\n'
            'pathlib.Path(sys.argv[1] + ".reko").mkdir()\n'
            'pathlib.Path(sys.argv[1] + ".reko/code_text.c").write_text("int main(){}\\n")\n'
            'os.write(1,b"analysis details\\n")\n'
            'os.write(2,b"analysis warning\\n")\n'
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'int main(){}\n')
        self.assertIn(b'analysis details', result.stderr)
        self.assertIn(b'analysis warning', result.stderr)

    def test_reko_diagnostic_flood_is_capped_by_parent(self):
        with self.assertRaises(OutputLimitExceeded):
            self.run_fake_reko(
                'import os;os.write(2,b"x" * 65536)\n', limit=1024,
            )


if __name__ == '__main__':
    unittest.main()
