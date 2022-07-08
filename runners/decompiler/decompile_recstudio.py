import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


RECSTUDIO_INSTALL = Path(os.getenv("RECSTUDIO_INSTALL_PATH", "/home/decompiler_user/bin"))
RECSTUDIO_CLI = RECSTUDIO_INSTALL / 'RecCLI'


def main():
    with tempfile.TemporaryDirectory() as tempdir:
        conts = sys.stdin.buffer.read()
        infile = tempfile.NamedTemporaryFile(dir=tempdir, delete=False)
        infile.write(conts)
        infile.flush()

        os.mkdir(tempdir + '/output')
        outfile = tempfile.NamedTemporaryFile(dir=tempdir + '/output', delete=False)
        outfile.close()

        decomp = subprocess.run([RECSTUDIO_CLI, infile.name, outfile.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if decomp.returncode != 0:
            print(f'{decomp.stdout.decode()}\n{decomp.stderr.decode()}')
            sys.exit(1)

        infile.close()

        with open(outfile.name, 'rb') as f:
            sys.stdout.buffer.write(f.read())


def version():
    with open(RECSTUDIO_CLI, 'rb') as f:
        # <h3>Welcome to RecStudio 4.1</h3>
        conts = f.read()
        assert b'<h3>Welcome to RecStudio ' in conts
        start = conts.find(b'<h3>Welcome to RecStudio ') + len(b'<h3>Welcome to RecStudio ')
        end = conts.find(b'</h3>', start)
        version = conts[start:end].decode()

    print(version)
    print()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--name':
        print('RecStudio')
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == '--url':
        print('https://www.backerstreet.com/rec/rec.htm')
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == '--version':
        version()
        sys.exit(0)

    main()
