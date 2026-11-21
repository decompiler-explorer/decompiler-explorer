"""Exercise the adapter without a running explorer server or Docker."""

import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest


ADAPTER = Path(__file__).with_name('decompile_objdump.py')


@unittest.skipUnless(shutil.which('objdump'), 'GNU objdump is required')
class ObjdumpTests(unittest.TestCase):
    def test_metadata(self):
        result = subprocess.run([sys.executable, str(ADAPTER), '--version'],
                                capture_output=True, check=True, text=True)
        self.assertIn('GNU objdump', result.stdout)
        self.assertEqual(len(result.stdout.splitlines()), 2)

    @unittest.skipUnless(Path('/bin/true').is_file(), 'native ELF fixture required')
    def test_native_binary_uses_stable_name(self):
        result = subprocess.run([sys.executable, str(ADAPTER)],
                                input=Path('/bin/true').read_bytes(),
                                capture_output=True, timeout=10, check=True)
        self.assertIn(b'input.bin:', result.stdout)
        self.assertIn(b'Disassembly of section', result.stdout)

    def test_invalid_input_preserves_error(self):
        result = subprocess.run([sys.executable, str(ADAPTER)], input=b'not an ELF',
                                capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'file format not recognized', result.stderr)


@unittest.skipUnless(os.name == 'posix', 'POSIX pipes and process groups required')
class StreamingTests(unittest.TestCase):
    def test_output_reaches_parent_while_objdump_is_still_running(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = Path(directory) / 'objdump'
            tool.write_text(f'#!{sys.executable}\n'
                            'import os,time\n'
                            'os.write(1,b"first chunk")\n'
                            'time.sleep(30)\n')
            tool.chmod(0o755)
            env = dict(os.environ, PATH=directory + os.pathsep + os.environ['PATH'])
            with subprocess.Popen([sys.executable, str(ADAPTER)], stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  env=env, start_new_session=True) as process:
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(process.stdout, selectors.EVENT_READ)
                        self.assertTrue(selector.select(timeout=5),
                                        'adapter buffered output until objdump exited')
                        self.assertEqual(os.read(process.stdout.fileno(), 100), b'first chunk')
                        self.assertIsNone(process.poll())
                finally:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()


if __name__ == '__main__':
    unittest.main()
