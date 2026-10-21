"""Guard the runner image's Python imports against incomplete Docker COPY steps."""

import re
import unittest
from pathlib import Path


class DockerfileRuntimeAssetsTests(unittest.TestCase):
    def test_each_runner_image_copies_output_capture(self):
        stages = {}
        current = None
        for line in Path(__file__).with_name('Dockerfile').read_text().splitlines():
            match = re.match(r'FROM (?:--platform=\S+ )?(\S+) AS (\S+)', line)
            if match:
                parent, current = match.groups()
                stages[current] = set(stages.get(parent, ()))
            elif current and line.startswith('COPY '):
                stages[current].update(line.split()[1:-1])
        runners = {name: files for name, files in stages.items()
                   if 'runner_generic.py' in files}
        self.assertTrue(runners)
        for name, files in runners.items():
            with self.subTest(stage=name):
                self.assertIn('output_capture.py', files)

    def test_base_stages_supply_runtime_to_future_runners(self):
        dockerfile = Path(__file__).with_name('Dockerfile').read_text()
        for base in ('base', 'base-trixie'):
            with self.subTest(base=base):
                block = re.search(r' AS ' + base + r'\n(.*?)(?=\nFROM |\Z)',
                                  dockerfile, re.S).group(1)
                self.assertIn('COPY output_capture.py .', block)


    def test_compose_exposes_output_budget(self):
        compose = Path(__file__).resolve().parents[2] / 'docker-compose.yml'
        self.assertIn(
            '- MAX_DECOMPILER_OUTPUT_BYTES=${MAX_DECOMPILER_OUTPUT_BYTES:-16777216}',
            compose.read_text(),
        )


if __name__ == '__main__':
    unittest.main()
