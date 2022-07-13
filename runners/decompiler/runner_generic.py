import argparse
from dataclasses import dataclass, asdict
import logging
import os
import resource
import subprocess
import sys
import threading
import time
import traceback

import requests

SERVER = os.environ.get('SERVER', 'http://127.0.0.1:8000')


@dataclass
class DecompilerInfo:
    name: str
    version: str
    revision: str
    url: str


class DecompileError(Exception):
    def __init__(self, message):
        self.message = message


def limit_memory(soft, hard):
    resource.setrlimit(resource.RLIMIT_AS, (soft, hard))


def decompile_source(args, compiled):
    try:
        proc = subprocess.run([sys.executable, args.script_name], input=compiled, capture_output=True, timeout=args.timeout, preexec_fn=lambda: limit_memory(args.mem_limit_soft, args.mem_limit_hard))
    except subprocess.TimeoutExpired:
        raise DecompileError("Exceeded time limit")

    if proc.returncode == 0:
        result = proc.stdout
        # Process did not crash but did not produce any stderr output.
        if len(result) == 0:
            raise DecompileError("Empty decompile result")
        return result
    else:
        raise DecompileError(f"{proc.stdout.decode()}\n{proc.stderr.decode()}")


class RunnerWrapper:
    def __init__(self) -> None:
        parser = argparse.ArgumentParser(description='Launch a decompiler script')
        parser.add_argument('script_name', help='Script to run')
        parser.add_argument('--timeout', type=int, default=None, help='Maximum time to spend decompiling each file')
        parser.add_argument('--mem-limit-hard', type=int, default=resource.RLIM_INFINITY, help='Hard memory limit for decompiling each file')
        parser.add_argument('--mem-limit-soft', type=int, default=resource.RLIM_INFINITY, help='Soft memory limit for decompiling each file')
        parser.add_argument('--debug', action='store_true', help='Log extra debug output')
        self.args = parser.parse_args()

        DECOMPILER_NAME = subprocess.check_output([sys.executable, self.args.script_name, '--name']).strip().decode()
        DECOMPILER_URL = subprocess.check_output([sys.executable, self.args.script_name, '--url']).strip().decode()
        version = subprocess.check_output([sys.executable, self.args.script_name, '--version']).decode()
        DECOMPILER_VERSION = version.split('\n')[0].strip()
        DECOMPILER_REVISION = version.split('\n')[1].strip()

        self.logger = logging.getLogger(f'{DECOMPILER_NAME} ({DECOMPILER_VERSION}-{DECOMPILER_REVISION})')
        logging.basicConfig()
        self.logger.setLevel(logging.DEBUG if self.args.debug else logging.INFO)

        self.logger.info("RUNNER CONFIG:")
        self.logger.info(f"   DECOMPILER NAME: {DECOMPILER_NAME}")
        self.logger.info(f"   DECOMPILER URL: {DECOMPILER_URL}")
        self.logger.info(f"   DECOMPILER VERSION: {DECOMPILER_VERSION}")
        self.logger.info(f"   DECOMPILER REVISION: {DECOMPILER_REVISION}")
        self.logger.info(f"   HOST SERVER: {SERVER}")

        self.decompiler_info = DecompilerInfo(
            name=DECOMPILER_NAME,
            version=DECOMPILER_VERSION,
            revision=DECOMPILER_REVISION,
            url=DECOMPILER_URL
        )

        try:
            with open('/run/secrets/worker_auth_token', 'r') as f:
                AUTH_TOKEN = f.read()
        except FileNotFoundError:
            self.logger.warning("Auth token file not found, using debug token")
            AUTH_TOKEN = "DEBUG_TOKEN"
            self.logger.info(f"   DEBUG MODE: True")

        self.session = requests.Session()
        self.session.headers.update({'X-AUTH-TOKEN': AUTH_TOKEN})

        self.decompiler_id = self.register_runner()
        self.pending_url = f'{SERVER}/api/decompilation_requests/?completed=false&decompiler={self.decompiler_id}'
        self.health_check_url = f'{SERVER}/api/decompilers/{self.decompiler_id}/health_check/'

        self.logger.info(f"   REMOTE ID: {self.decompiler_id}")

        threading.Thread(target=self.health_check).start()


    def register_runner(self) -> str:
        decompilers_url = f'{SERVER}/api/decompilers/'
        req = self.session.get(decompilers_url)
        if req.status_code != 200:
            raise Exception(req.text)

        decompiler_id = None
        decompilers = req.json()['results']
        for d in decompilers:
            info = DecompilerInfo(
                name=d['name'],
                version=d['version'],
                revision=d['revision'],
                url=d['url'],
            )
            if info == self.decompiler_info:
                decompiler_id = d['id']
                break

        if decompiler_id is None:
            req = self.session.post(decompilers_url, json=asdict(self.decompiler_info))
            if req.status_code != 201:
                raise Exception(req.text)
            decompiler_id = req.json()['id']

        if decompiler_id is None:
            raise Exception('Cannot find decompiler')

        return decompiler_id


    def health_check(self):
        while True:
            try:
                r = self.session.get(self.health_check_url)
                assert r.status_code == 200
            except:
                self.logger.error("Health check failed")
                self.logger.error(traceback.format_exc())
            time.sleep(10)


    def run(self):
        backoff_factor = 1
        retry_count = 0
        max_sleep_time = 30

        while True:
            try:
                req = self.session.get(self.pending_url).json()

                for pending_req in req['results'][:1]:
                    self.logger.info(f"Got decompilation request for {pending_req['binary_id']} (req: {pending_req['id']})")
                    self.logger.debug(f"<<< %s", pending_req)
                    compiled_conts = self.session.get(pending_req['download_url']).content
                    self.logger.debug("Starting decompilation")
                    start_time = time.time()
                    try:
                        decompiled = decompile_source(self.args, compiled_conts)
                        end_time = time.time()
                        self.logger.debug("Decompilation finished")

                        data = {
                            'request': pending_req['id'],
                            'analysis_time': end_time - start_time,
                        }
                        files = {
                            'decompiled_file': decompiled,
                        }

                        r = self.session.post(pending_req['decompilations_url'], data=data, files=files)

                        self.logger.debug(">>> %s", r.text)
                        self.logger.info(f"Decompilation request for {pending_req['binary_id']} (req: {pending_req['id']}) finished with success")
                    except DecompileError as e:
                        end_time = time.time()
                        self.logger.error(f"DECOMPILE ERROR: {e.message}")
                        data = {
                            'error': e.message,
                            'request': pending_req['id'],
                            'analysis_time': end_time - start_time,
                        }
                        r = self.session.post(pending_req['decompilations_url'], data=data)
                        self.logger.debug(r.text)

            except KeyboardInterrupt:
                break
            except Exception as e:
                self.logger.error(e)
                self.logger.error(traceback.format_exc())
                sleep_time = min(backoff_factor * (2**(retry_count - 1)), max_sleep_time)
                self.logger.info(f"Request failed, trying again in {sleep_time} seconds")
                time.sleep(sleep_time)
                retry_count += 1
            else:
                retry_count = 0

            time.sleep(1)


if __name__ == '__main__':
    wrapper = RunnerWrapper()
    wrapper.run()
