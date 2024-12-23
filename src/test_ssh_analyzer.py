# -*- coding: utf-8 -*-
# Copyright 2022 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Task for Linux SSH analysis."""

import pytest
import datetime
import mock
import os
import pandas as pd
import shutil

import ssh_analyzer

# from turbinia.evidence import RawDisk
# from turbinia.workers import Priority
# from turbinia.workers import TurbiniaTaskResult
# from turbinia.workers.workers_test import TestTurbiniaTaskBase
from openrelik_worker_common.reporting import Priority

class TestLinuxSSHAnalysisTask():
  """Test for LinuxSSHAnalysisTask task."""

  def setUp(self):
    super(TestLinuxSSHAnalysisTask, self).setUp(
        task_class=ssh_analyzer.LinuxSSHAnalysisTask)

    self.task.output_dir = self.task.base_output_dir
    self.output_file_path = os.path.join(
        self.task.output_dir, 'linux_ssh_analysis.md')
    self.remove_files.append(self.output_file_path)
    os.makedirs(os.path.join(self.task.output_dir, 'var', 'log'))
    self.setResults(mock_run=False)

  def tearDown(self):
    if os.path.exists(self.base_output_dir):
      shutil.rmtree(self.base_output_dir)

  def test_parse_log_data(self):
    """Test parsing SSH log file"""
    log_file = os.path.join('test_data', 'secure')
    if not os.path.exists(log_file):
      raise FileNotFoundError(f'{log_file} does not exist.')

    with open(log_file, 'r', encoding='utf-8') as fh:
      data = fh.read()
    a = ssh_analyzer.LinuxSSHAnalysisTask()
    ssh_records = a.parse_log_data(data, log_file, log_year=2022)
    assert len(ssh_records) == 27719

  def test_read_logs(self):
    """Test read_logs method."""
    analyzer = ssh_analyzer.LinuxSSHAnalysisTask()

    print('[+] Checking empty input_files')
    result = analyzer.read_logs(input_files='')
    assert result.empty

    _INPUT_FILES = [{'id': 1, 'uuid': '445027ec76ef42f8a463fdbaf162d2b7', 'display_name': 'secure', 'extension': '', 'data_type': 'file:generic', 'path': 'test_data/secure'}]
    print('[+] Checking test_data/secure as input_files')
    result = analyzer.read_logs(input_files=_INPUT_FILES)
    assert len(result) == 27719

  @pytest.mark.skipif(
    datetime.datetime.now().astimezone().tzname() != 'UTC',
    reason='This test must be run on a UTC-configured machine'
  )
  def test_parse_message_datetime(self):
    """Test parsing message datetime fields."""
    analyzer = ssh_analyzer.LinuxSSHAnalysisTask()

    # Testing Feb 8 13:30:45 Debian/CentOS format
    output = analyzer.parse_message_datetime(
        message_datetime=['Feb', '8', '13:30:45'], log_year=2023)
    expected_output = datetime.datetime(
        2023, 2, 8, 13, 30, 45, tzinfo=datetime.timezone.utc)
    assert output == expected_output

    # Testing 2023-02-08T13:30:45.123456+11:00 OpenSUSE format
    output = analyzer.parse_message_datetime(
        message_datetime=['2023-02-08T13:30:45.123456+11:00'], log_year=0)
    expected_output = datetime.datetime(
        2023, 2, 8, 2, 30, 45, 123456, datetime.timezone.utc)
    assert output == expected_output

    # Invalid datetime 2023-13-10 22:10:10
    output = analyzer.parse_message_datetime(
        message_datetime=['2023-13-10 22:10:10'], log_year=0)
    assert output is None

    # Invalid datetime random
    output = analyzer.parse_message_datetime(['random'], log_year=0)
    assert output is None

  @mock.patch('turbinia.lib.utils.extract_artifacts')
  @mock.patch(
      'turbinia.workers.analysis.ssh_analyzer.LinuxSSHAnalysisTask.brute_force_analysis'
  )
  @mock.patch(
      'turbinia.workers.analysis.ssh_analyzer.LinuxSSHAnalysisTask.read_logs')
  @pytest.mark.skip
  def test_run(
      self, mock_read_logs, mock_brute_force_analysis, mock_extract_artifacts):
    """Test LinuxSSHAnalysis task run."""
    self.task.setup(self.task)

    mock_extract_artifacts.return_value = ['secure', 'var/log/secure']

    log_file = os.path.join('test_data', 'secure')
    if not os.path.exists(log_file):
      raise FileNotFoundError(f'{log_file} does not exist.')

    with open(log_file, 'r', encoding='utf-8') as fh:
      data = fh.read()
    a = ssh_analyzer.LinuxSSHAnalysisTask()
    ssh_records = a.parse_log_data(data, log_file, log_year=2022)
    df = pd.DataFrame(ssh_records)

    mock_read_logs.return_value = df

    mock_brute_force_analysis.return_value = (
        Priority.MEDIUM, 'Brute force from 1 IP addresses',
        '## Brute Force Analysis\n\n### Brute Force from 192.168.40.6\n\n'
        '- Successful brute force from 192.168.40.6 as admin at 2022-10-08'
        ' 18:10:33 (duration=7)')

    result = self.task.run(self.evidence, self.result)

    self.assertIsInstance(result, TurbiniaTaskResult)
    self.assertEqual(
        result.report_data,
        '## Brute Force Analysis\n\n### Brute Force from 192.168.40.6\n\n'
        '- Successful brute force from 192.168.40.6 as admin at 2022-10-08'
        ' 18:10:33 (duration=7)')


class TurbiniaTaskResult:
  pass