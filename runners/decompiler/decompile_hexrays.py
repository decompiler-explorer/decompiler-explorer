import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

IDA_INSTALL = Path(os.getenv("IDA_INSTALL_PATH", "/home/decompiler_user/ida"))
IDA_IDAT = IDA_INSTALL / 'idat'
IDA_BATCH_PY = IDA_INSTALL / 'batch.py'
IDA_VERSION_PY = IDA_INSTALL / 'version.py'


def main():
    with tempfile.TemporaryDirectory() as tempdir:
        conts = sys.stdin.buffer.read()
        infile = tempfile.NamedTemporaryFile(dir=tempdir, delete=False)
        infile.write(conts)
        infile.flush()
        output = infile.name + ".c"

        decomp = subprocess.run([sys.executable, str(IDA_BATCH_PY), "--idadir", str(IDA_INSTALL), infile.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if decomp.returncode != 0 or not Path(output).exists():
            print(f'{decomp.stdout.decode()}\n{decomp.stderr.decode()}')
            sys.exit(1)
        infile.close()

        with open(output, 'rb') as f:
            sys.stdout.buffer.write(f.read())


def version():
    logpath = Path(os.getcwd()) / 'ida.log'

    try:
        # TODO: Is there a way to do this without creating an idb?
        with tempfile.TemporaryDirectory() as tmp:
            dummy_path = Path(tmp) / 'dummy'
            with open(dummy_path, 'wb') as dummy_file:
                dummy_file.write(b'\x00' * 256)
                subprocess.run([str(IDA_IDAT), '-A', '-a',
                                f'-S{IDA_VERSION_PY}', f'-L{logpath}', str(dummy_path)])
            version = open(dummy_path.parent / 'version.txt').read().strip()
    except Exception as e:
        with open(logpath, 'r') as f:
            print(f.read(), file=sys.stderr)
        raise e

    print(version)
    print()  # Not given


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--name':
        print('Hex-Rays')
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == '--url':
        print('https://hex-rays.com/ida-pro/')
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == '--version':
        version()
        sys.exit(0)

    main()
