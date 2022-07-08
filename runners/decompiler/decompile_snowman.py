import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


SNOWMAN_INSTALL = Path(os.getenv("SNOWMAN_INSTALL_PATH", "/home/decompiler_user/install/bin"))
SNOWMAN_NOCODE = SNOWMAN_INSTALL / 'nocode'


def main():
    with tempfile.TemporaryDirectory() as tempdir:
        conts = sys.stdin.buffer.read()
        infile = tempfile.NamedTemporaryFile(dir=tempdir, delete=False)
        infile.write(conts)
        infile.flush()

        decomp = subprocess.run([SNOWMAN_NOCODE, infile.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if decomp.returncode != 0:
            print(f'{decomp.stdout.decode()}\n{decomp.stderr.decode()}')
            sys.exit(1)
        infile.close()

        sys.stdout.buffer.write(decomp.stdout)


def version():
    proc = subprocess.run([SNOWMAN_NOCODE, '--help'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Version: v0.1.3-13-g6fed71c
    output = proc.stdout.decode()
    lines = output.split('\n')
    version_lines = [l for l in lines if l.startswith('Version: ')]
    assert len(version_lines) == 1
    revision = version_lines[0][-8:]
    version = version_lines[0][10:-9]

    print(version)
    print(revision)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--name':
        print('Snowman')
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == '--url':
        print('https://github.com/yegord/snowman')
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == '--version':
        version()
        sys.exit(0)

    main()
