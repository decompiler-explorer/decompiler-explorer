"""Bounded, memory-safe subprocess output capture for decompiler runners."""

import os
import selectors
import signal
import subprocess
import tempfile
import time


MAX_OUTPUT_BYTES = int(os.environ.get("MAX_DECOMPILER_OUTPUT_BYTES", 16 * 1024 * 1024))


class OutputLimitExceeded(Exception):
    """The decompiler produced more than the configured output budget."""


def bounded_diagnostic(data, max_bytes=8192):
    """Keep failed decompilations from persisting megabytes of log text."""
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    preview = data[:max_bytes].decode(errors='replace')
    if len(data) > max_bytes:
        preview += "\n...[truncated]"
    return preview



def run_with_bounded_output(command, *, input_bytes=b'', timeout=None, cwd=None,
                            preexec_fn=None, max_output_bytes=16 * 1024 * 1024):
    """Run a subprocess without buffering unbounded output in memory.

    Both stdout and stderr count toward the shared cap. Stdin comes from a
    temporary file so a verbose child cannot deadlock on a full stdin pipe.
    A new process session allows us to terminate the child and descendants
    on timeout, output overflow, or interrupted execution.
    """
    if max_output_bytes <= 0:
        raise ValueError("max_output_bytes must be positive")

    with tempfile.TemporaryFile() as stdin_file:
        stdin_file.write(input_bytes)
        stdin_file.seek(0)
        process = subprocess.Popen(
            command,
            stdin=stdin_file,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            preexec_fn=preexec_fn,
            start_new_session=True,
        )
        # Bytearrays avoid retaining millions of Python objects if a child
        # writes a large number of tiny chunks.
        chunks = {'stdout': bytearray(), 'stderr': bytearray()}
        captured_bytes = 0
        deadline = None if timeout is None else time.monotonic() + timeout

        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
                selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
                while selector.get_map():
                    remaining = None if deadline is None else deadline - time.monotonic()
                    if remaining is not None and remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    for key, _ in selector.select(remaining):
                        data = os.read(key.fileobj.fileno(), 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        captured_bytes += len(data)
                        if captured_bytes > max_output_bytes:
                            raise OutputLimitExceeded(
                                f"Decompiler output exceeded {max_output_bytes} bytes"
                            )
                        chunks[key.data].extend(data)

            remaining = None if deadline is None else max(0, deadline - time.monotonic())
            process.wait(timeout=remaining)
            return subprocess.CompletedProcess(
                command,
                process.returncode,
                bytes(chunks['stdout']),
                bytes(chunks['stderr']),
            )
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
        finally:
            process.stdout.close()
            process.stderr.close()
