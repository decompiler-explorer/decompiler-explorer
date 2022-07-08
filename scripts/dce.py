import argparse
import os
import secrets
import subprocess
import sys

from pathlib import Path

REQUIRED_SECRETS = [
    'db_superuser_pass',
    'worker_auth_token',
]

BASE_DIR = Path(__file__).parent.parent
SECRETS_DIR = BASE_DIR / 'secrets'
DATA_DIR = BASE_DIR / 'db_data'


DECOMPILERS = [
    ('angr',        'angr'),
    ('boomerang',   'Boomerang'),
    ('ghidra',      'Ghidra'),
    ('recstudio',   'REC Studio'),
    ('reko',        'Reko'),
    ('retdec',      'RetDec'),
    ('snowman',     'Snowman')
]

if not (BASE_DIR / 'runners' / 'decompiler' / 'tools' / 'binja' / 'license.dat').exists():
    print("Binary Ninja key not detected... Excluding from build")
else:
    DECOMPILERS.append(('binja', 'Binary Ninja'))

if not (BASE_DIR / 'runners' / 'decompiler' / 'tools' / 'hexrays' / '.idapro' / 'ida.reg').exists() or \
    not (BASE_DIR / 'runners' / 'decompiler' / 'tools' / 'hexrays' / 'ida' / 'idat64').exists() or \
    not (BASE_DIR / 'runners' / 'decompiler' / 'tools' / 'hexrays' / 'efd64').exists():
    print("IDA install key not detected... Excluding from build")
else:
    DECOMPILERS.append(('hexrays', 'Hex Rays'))

DECOMPILERS.sort(key=lambda d: d[0])

parser = argparse.ArgumentParser(description='Manage decompiler explorer')
for decomp in DECOMPILERS:
    parser.add_argument(f'--without-{decomp[0]}', dest=decomp[0], action='store_false', help=f'Disable {decomp[1]} decompiler')

for decomp in DECOMPILERS:
    parser.add_argument(f'--with-{decomp[0]}', dest=decomp[0], action='store_true', help=f'Enable {decomp[1]} decompiler')

subparsers = parser.add_subparsers(dest='subcommand_name')

init_parser = subparsers.add_parser('init')
init_parser.add_argument('--force', action='store_true', help='Overwrite existing files')

build_parser = subparsers.add_parser('build')
build_parser.add_argument('--prod', action='store_true', help='Build for production')

start_parser = subparsers.add_parser('start')
start_parser.add_argument('--debug', action='store_true', help='Show debug output')
start_parser.add_argument('--prod', action='store_true', help='Start production server')
start_parser.add_argument('--acme-email', default="admin@localhost", help='Email address for ACME notifications')
start_parser.add_argument('--domain', default="dce.localhost", help='Domain name of host')
start_parser.add_argument('--s3', action='store_true', help='Use S3 for storing uploaded files')
start_parser.add_argument('--s3-bucket', required='--argument' in sys.argv, help='Name of S3 bucket that will store uploaded files')

stop_parser = subparsers.add_parser('stop')
stop_parser.add_argument('--prod', action='store_true', help='Stop production server')


def _generate_secrets(force=False):
    if not SECRETS_DIR.exists():
        SECRETS_DIR.mkdir()

    for secret_name in REQUIRED_SECRETS:
        secret_path = SECRETS_DIR / secret_name
        if secret_path.exists() and not force:
            print(f"Secret {secret_name} already exists, skipping...")
            continue
        print(f"Generating secret {secret_name}...")
        secret_path.touch(mode=0o600)
        secret_path.write_text(secrets.token_hex(32))


def init_server(args):
    if not DATA_DIR.exists():
        DATA_DIR.mkdir()
    _generate_secrets(args.force)


def build_server(args):
    config_files = '-f docker-compose.yml'
    if args.prod:
        config_files += ' -f docker-compose.prod.yml'

    services = [
        'traefik',
        'database',
        'explorer'
    ]
    for d in DECOMPILERS:
        if getattr(args, d[0]):
            services.append(d[0])

    cmd = f"docker-compose {config_files} build"
    subprocess.run(cmd.split(' ') + services)


def start_server(args):
    config_files = '-c docker-compose.yml'
    if args.prod:
        config_files += ' -c docker-compose.prod.yml'

    env = {
        'LETSENCRYPT_ACME_EMAIL': args.acme_email,
        'DOMAIN': args.domain,
        'PATH': os.environ['PATH']
    }

    if 'DECOMPILER_TIMEOUT' in os.environ:
        env['DECOMPILER_TIMEOUT'] = os.environ['DECOMPILER_TIMEOUT']

    if args.s3:
        config_files += ' -c docker-compose.s3.yml'
        env["AWS_STORAGE_BUCKET_NAME"] = args.s3_bucket

    if args.debug:
        env['DEBUG'] = '1'

    cmd = f"docker stack deploy {config_files} --prune dogbolt"

    subprocess.run(cmd.split(' '), env=env)


def stop_server():
    cmd = f"docker stack rm dogbolt"
    subprocess.run(cmd.split(' '))


args = parser.parse_args()
subcommand = args.subcommand_name

if subcommand == 'init':
    init_server(args)
elif subcommand == 'build':
    build_server(args)
elif subcommand == 'start':
    start_server(args)
elif subcommand == 'stop':
    stop_server()
else:
    parser.print_help()
