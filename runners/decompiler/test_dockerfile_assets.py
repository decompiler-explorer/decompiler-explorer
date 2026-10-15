"""Guard the runner image's Python imports against incomplete Docker COPY steps."""

import re
import unittest
from pathlib import Path


class DockerfileRuntimeAssetsTests(unittest.TestCase):
    def test_each_runner_image_copies_output_capture(self):
        dockerfile = Path(__file__).with_name('Dockerfile').read_text()
        stages = re.split(r'(?m)^FROM\s+[^\n]+\s+AS\s+(\S+)\s*$', dockerfile)
        self.assertGreater(len(stages), 1, 'Expected named Docker build stages')
        runner_stages = []
        for stage_name, instructions in zip(stages[1::2], stages[2::2]):
            if 'ENTRYPOINT [ "./entrypoint.sh"' not in instructions:
                continue
            runner_stages.append(stage_name)
            self.assertIn(
                'COPY runner_generic.py output_capture.py ./', instructions,
                f'{stage_name} image must include the runner\'s imported output_capture module',
            )
        self.assertGreater(len(runner_stages), 0, 'Expected at least one runner image')

    def test_compose_exposes_output_budget(self):
        compose = Path(__file__).resolve().parents[2] / 'docker-compose.yml'
        self.assertIn(
            '- MAX_DECOMPILER_OUTPUT_BYTES=${MAX_DECOMPILER_OUTPUT_BYTES:-16777216}',
            compose.read_text(),
        )


if __name__ == '__main__':
    unittest.main()
