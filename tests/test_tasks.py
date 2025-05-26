# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import json
import filecmp
from src.tasks import run_ssh_analyzer

_INPUT_FILES = [
    {
        "id": 1,
        "uuid": "445027ec76ef42f8a463fdbaf162d2b7",
        "display_name": "secure",
        "extension": "",
        "data_type": "file:generic",
        "path": "test_data/secure",
    }
]


class TestTasks:
    def test_run_ssh_analyzer(self):
        """Test LinuxSSHAnalysis task run."""

        output = run_ssh_analyzer(
            input_files=_INPUT_FILES,
            output_path="/tmp",
            workflow_id="deadbeef",
            task_config={},
        )

        output_dict = json.loads(base64.b64decode(output))
        output_path = output_dict.get("output_files")[0].get("path")
        assert filecmp.cmp(
            output_path, "test_data/linux_ssh_analysis.md", shallow=False
        )
