import pytest
import base64
import json
import filecmp
from tasks import run_ssh_analyzer

_INPUT_FILES = [{'id': 1, 'uuid': '445027ec76ef42f8a463fdbaf162d2b7', 'display_name': 'secure', 'extension': '', 'data_type': 'file:generic', 'path': 'test_data/secure'}]

  # @mock.patch(
  #     'ssh_analyzer.LinuxSSHAnalysisTask.brute_force_analysis'
  # )
  # @mock.patch(
  #     'ssh_analyzer.LinuxSSHAnalysisTask.read_logs')

class TestTasks():
  def test_run_ssh_analyzer(self):
    """Test LinuxSSHAnalysis task run."""
    
    output = run_ssh_analyzer(self, input_files=_INPUT_FILES, output_path='/tmp', workflow_id='deadbeef')

    output_dict = json.loads(base64.b64decode(output))
    output_path = output_dict.get('output_files')[0].get('path')
    assert(filecmp.cmp(output_path, 'test_data/linux_ssh_analysis.md', shallow=False))
