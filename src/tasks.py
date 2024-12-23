# Copyright 2024 Google LLC
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

import subprocess

from openrelik_worker_common.file_utils import create_output_file
from openrelik_worker_common.task_utils import create_task_result, get_input_files

from ssh_analyzer import LinuxSSHAnalysisTask

from .app import celery

# Task name used to register and route the task to the correct queue.
TASK_NAME = "openrelik-worker-analyzer-logs.tasks.ssh_analyzer"

# Task metadata for registration in the core system.
TASK_METADATA = {
    "display_name": "SSH login analyzer",
    "description": "Search for suspicious SSH login events in system logs",
    # Configuration that will be rendered as a web for in the UI, and any data entered
    # by the user will be available to the task function when executing (task_config).
    # "task_config": [
    #     {
    #         "name": "<REPLACE_WITH_NAME>",
    #         "label": "<REPLACE_WITH_LABEL>",
    #         "description": "<REPLACE_WITH_DESCRIPTION>",
    #         "type": "<REPLACE_WITH_TYPE>",  # Types supported: text, textarea, checkbox
    #         "required": False,
    #     },
    # ],
}


@celery.task(bind=True, name=TASK_NAME, metadata=TASK_METADATA)
def ssh_analyzer(
    self,
    pipe_result: str = None,
    input_files: list = None,
    output_path: str = None,
    workflow_id: str = None,
    task_config: dict = None,
) -> str:
    """Run <REPLACE_WITH_COMMAND> on input files.

    Args:
        pipe_result: Base64-encoded result from the previous Celery task, if any.
        input_files: List of input file dictionaries (unused if pipe_result exists).
        output_path: Path to the output directory.
        workflow_id: ID of the workflow.
        task_config: User configuration for the task.

    Returns:
        Base64-encoded dictionary containing task results.
    """
    input_files = get_input_files(pipe_result, input_files or [])
    output_files = []

    ssh_analysis_task = LinuxSSHAnalysisTask()

    for input_file in input_files:
        output_file = create_output_file(
            output_path,
            display_name=input_file.get("display_name"),
            extension=".ssh_report.txt",
            data_type="openrelik:ssh:report",
        )
        with open(output_file.path, "w") as outfile:
            with open(input_file.get("path", "r")) as infile:
                for line in infile:
                    if "ssh" in line:
                        outfile.write(line)
                
        output_files.append(output_file.to_dict())

    if not output_files:
        raise RuntimeError("No output files")

    return create_task_result(
        output_files=output_files,
        workflow_id=workflow_id,
        # command=base_command_string,
        meta={},
    )

def run(
      self, evidence: Evidence,
      result: TurbiniaTaskResult) -> TurbiniaTaskResult:
    """Runs the SSH Auth Analyzer worker.

    Args:
      evidence (Evidence object): The evidence being processed by analyzer.
      result (TurbiniaTaskResult): The object to place task results into.

    Returns:
      TurbiniaTaskResult object.
    """

    # Output file and evidence
    output_file_name = 'linux_ssh_analysis.md'
    output_file_path = os.path.join(self.output_dir, output_file_name)
    output_evidence = ReportText(source_path=output_file_path)

    # Analyzer outputs
    analyzer_output_priority = Priority.LOW
    analyzer_output_summary = ''
    analyzer_output_report = ''
    output_summary_list = []
    output_report_list = []

    try:
      collected_artifacts = extract_artifacts(
          artifact_names=['LinuxAuthLogs'], disk_path=evidence.local_path,
          output_dir=self.output_dir, credentials=evidence.credentials)
      result.log(f'collected artifacts: {collected_artifacts}')
    except TurbiniaException as exception:
      result.close(self, success=False, status=str(exception))
      return result

    log_dir = os.path.join(self.output_dir, 'var', 'log')
    result.log(f'Checking log directory {log_dir}')

    if not os.path.exists(log_dir):
      summary = f'No SSH log directory in {log_dir}'
      result.close(self, success=True, status=summary)
      return result

    df = self.read_logs(log_dir=log_dir)
    if df.empty:
      summary = f'No SSH authentication events in {evidence.local_path}.'
      result.close(self, success=True, status=summary)
      return result

    # 01. Brute Force Analyzer
    (result_priority, result_summary,
     result_markdown) = self.brute_force_analysis(df)
    if result_priority < analyzer_output_priority:
      analyzer_output_priority = result_priority
    output_summary_list.append(result_summary)
    output_report_list.append(result_markdown)

    # TODO(rmaskey): 02. Last X-Days Analyzer
    # TODO(rmaskey): 03. NICE Analyzer

    # 04. Handling result
    if output_summary_list:
      analyzer_output_summary = '. '.join(output_summary_list)
    else:
      analyzer_output_summary = 'No findings for SSH authentication analyzer.'

    if output_report_list:
      analyzer_output_report = '\n'.join(output_report_list)
    else:
      analyzer_output_report = 'No finding for SSH authentication analyzer.'

    result.report_priority = analyzer_output_priority
    result.report_data = analyzer_output_report
    output_evidence.text_data = analyzer_output_report

    # 05. Write the report to the output file.
    with open(output_file_path, 'wb') as fh:
      fh.write(output_evidence.text_data.encode('utf-8'))

    # Add the resulting evidence to the result object.
    result.add_evidence(output_evidence, evidence.config)
    result.close(self, success=True, status=analyzer_output_summary)
    return result
