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

import hashlib
import logging
import re
import pyparsing
import pandas as pd
import gzip

from datetime import datetime, timezone
from typing import Tuple, List
from .auth_log_analyzer import BruteForceAnalyzer
from openrelik_worker_common.reporting import Priority

log = logging.getLogger(__name__)


class SSHEventData:
    """SSH authentication event."""

    def __init__(
        self,
        timestamp: int,
        date: str,
        time: str,
        hostname: str,
        pid: int,
        event_key: str,
        event_type: str,
        auth_method: str,
        auth_result: str,
        username: str,
        source_ip: str,
        source_port: int,
        source_hostname: str,
    ):
        self.timestamp = timestamp
        self.date = date
        self.time = time
        self.hostname = hostname
        self.pid = pid
        self.event_key = event_key
        self.event_type = event_type
        self.auth_method = auth_method
        self.auth_result = auth_result
        self.domain = ""  # Required for consistency with Windows
        self.username = username
        self.source_ip = source_ip
        self.source_port = source_port
        self.source_hostname = source_hostname
        self.session_id = None

    def calculate_session_id(self) -> None:
        """Calculates pseudo session_id for SSH login.

        The pseudo session_id is based on date, hostname, username, source_ip,
        and source_port.
        """
        # TODO(rmaskey): Find a better way to generate pseudo session_id. Current
        # method fails if the date changes between login and logoff.
        hash_data = (
            f"{self.date}|{self.hostname}|{self.username}|{self.source_ip}|"
            f"{self.source_port}"
        )

        h = hashlib.new("sha256")
        h.update(str.encode(hash_data))
        self.session_id = h.hexdigest()


class LinuxSSHAnalysisTask:
    # Log year validation
    # The minimum supported log year
    # NOTE: Python supports 1 as minimum year in datetime
    MIN_LOG_YEAR = 1970

    # Maximum supported valid log year
    # NOTE: Python datetime supports 9999 as maximum year
    MAX_LOG_YEAR = 9999

    # Standard SSH authentication log
    _MONTH = pyparsing.Word(pyparsing.alphas, max=3).setResultsName("month")
    _DAY = pyparsing.Word(pyparsing.nums, max=2).setResultsName("day")
    _TIME = pyparsing.Word(pyparsing.printables, max=9).setResultsName("time")

    _DATETIME_DEFAULT = _MONTH + _DAY + _TIME

    # Default datetime format for OpenSUSE
    _DATETIME_SUSE = pyparsing.Word(pyparsing.printables)
    _DATETIME = (_DATETIME_DEFAULT | _DATETIME_SUSE).setResultsName("datetime")

    _HOSTNAME = pyparsing.Word(pyparsing.printables).setResultsName("hostname")
    _PID = pyparsing.Word(pyparsing.nums).setResultsName("pid")
    _AUTHENTICATION_METHOD = (
        pyparsing.Keyword("password") | pyparsing.Keyword("publickey")
    ).setResultsName("auth_method")
    _USERNAME = pyparsing.Word(pyparsing.printables).setResultsName("username")
    _SOURCE_IP = pyparsing.Word(pyparsing.printables).setResultsName("source_ip")
    _SOURCE_PORT = pyparsing.Word(pyparsing.nums, max=5).setResultsName("source_port")
    _PROTOCOL = pyparsing.Word(pyparsing.printables).setResultsName("protocol")
    _FINGERPRINT_TYPE = pyparsing.Word(pyparsing.alphanums).setResultsName(
        "fingerprint_type"
    )
    _FINGERPRINT = pyparsing.Word(pyparsing.printables).setResultsName("fingerprint")

    # SSH event grammar
    _LOGIN_GRAMMAR = (
        _DATETIME
        + _HOSTNAME
        + pyparsing.Literal("sshd[")
        + _PID
        + pyparsing.Literal("]:")
        + pyparsing.Literal("Accepted")
        + _AUTHENTICATION_METHOD
        + pyparsing.Literal("for")
        + _USERNAME
        + pyparsing.Literal("from")
        + _SOURCE_IP
        + pyparsing.Literal("port")
        + _SOURCE_PORT
        + _PROTOCOL
        + pyparsing.Optional(_FINGERPRINT_TYPE + _FINGERPRINT)
        + pyparsing.StringEnd()
    )

    _FAILED_GRAMMAR = (
        _DATETIME
        + _HOSTNAME
        + pyparsing.Literal("sshd[")
        + _PID
        + pyparsing.Literal("]:")
        + pyparsing.Literal("Failed")
        + _AUTHENTICATION_METHOD
        + pyparsing.Literal("for")
        + pyparsing.Optional(pyparsing.Literal("invalid") + pyparsing.Literal("user"))
        + _USERNAME
        + pyparsing.Literal("from")
        + _SOURCE_IP
        + pyparsing.Literal("port")
        + _SOURCE_PORT
        + _PROTOCOL
    )

    _DISCONNECT_GRAMMAR = (
        _DATETIME
        + _HOSTNAME
        + pyparsing.Literal("sshd[")
        + _PID
        + pyparsing.Literal("]:")
        + pyparsing.Literal("Disconnected")
        + pyparsing.Literal("from")
        + pyparsing.Literal("user")
        + _USERNAME
        + _SOURCE_IP
        + pyparsing.Literal("port")
        + _SOURCE_PORT
    )

    MESSAGE_GRAMMAR = {
        "accepted": _LOGIN_GRAMMAR,
        "failed": _FAILED_GRAMMAR,
        "disconnected": _DISCONNECT_GRAMMAR,
    }

    def __init__(self, log_year=None):
        self.log_year = log_year

    def read_logs(self, input_files: list) -> pd.DataFrame:
        """Reads SSH logs directory and returns Pandas dataframe.

        Args:
          input_files (list): List of files containing SSH authentication logs.

        Returns:
          pd.DataFrame: Pandas dataframe.
        """
        if not input_files:
            return pd.DataFrame()

        ssh_records = []

        for input_file in input_files:
            # We only want to process files that hold SSH events.
            log_filename = input_file.get("display_name")
            if (
                not log_filename.startswith("auth.log")
                and not log_filename.startswith("secure")
                and not log_filename.startswith("message")
            ):
                continue

            log_file = input_file.get("path")
            log.debug("Processing log file %s", log_file)

            # Handle log archive
            if log_filename.endswith(".gz"):
                try:
                    with gzip.open(log_file, "rt", encoding="ISO-8859–1") as fh:
                        log_data = fh.read()
                        records = self.parse_log_data(
                            log_data, log_filename=log_filename, log_year=self.log_year
                        )
                        if records:
                            ssh_records += records
                except gzip.BadGzipFile as e:
                    log.error(
                        "Error opening a bad gzip file %s. %s", log_filename, {str(e)}
                    )
                except OSError as e:
                    log.error("%s does not exist. %s", log_filename, str(e))
                finally:
                    continue

            # Handle standard log file
            try:
                with open(log_file, "r", encoding="ISO-8859–1") as fh:
                    log_data = fh.read()
                    records = self.parse_log_data(
                        log_data, log_filename=log_filename, log_year=self.log_year
                    )
                    if records:
                        ssh_records += records
            except (FileNotFoundError, OSError) as e:
                log.error("%s does not exist. %s", log_file, str(e))
            finally:
                continue

        if not ssh_records:
            log.info("No SSH authentication events in %s", log_filename)
            return pd.DataFrame()
        log.info("Total number of SSH authentication events: %d", len(ssh_records))

        ssh_data = []
        for ssh_record in ssh_records:
            ssh_data.append(ssh_record.__dict__)
        df = pd.DataFrame(ssh_data)
        return df

    def parse_message_datetime(self, message_datetime: List, log_year: int) -> datetime:
        """Parses and returns datetime.

        Args:
          message_datetime (List[str]): A list containing syslog datetime separated
              by spaces e.g. Feb 8 13:30:45 for Debian, and Red Hat, and
              2023-02-08T13:30:45.123456+11:00 for OpenSUSE.
          log_year (int): A user provided log year for SSH events. The log year is
          not captured by syslog and this is either provided by user or guessed
          based on the last SSH event and current date/time.

        Returns:
          datetime.datetime: Returns datetime.datetime object or None.
        """
        # NOTE: returned datetime object contains naive datetime
        # TODO(rmaskey): Better handle date time and timezone
        try:
            if len(message_datetime) == 1:
                # e.g. OpenSUSE syslog datetime format 2023-02-08T13:30:45.123456+11:00
                return datetime.fromisoformat(message_datetime[0]).astimezone(
                    timezone.utc
                )
            elif len(message_datetime) == 3:
                # e.g. Debian/Red Hat Feb 8 13:30:45
                datetime_string = (
                    f"{message_datetime[0]} {message_datetime[1]}"
                    f" {log_year} {message_datetime[2]}"
                )
                return datetime.strptime(
                    datetime_string, "%b %d %Y %H:%M:%S"
                ).astimezone(timezone.utc)
            else:
                return datetime.fromtimestamp(0).astimezone(timezone.utc)
        except ValueError:
            log.error("Invalid datetime format %s", " ".join(message_datetime))
        return None

    def parse_log_data(
        self, data, log_filename: str, log_year: int = None
    ) -> List[SSHEventData]:
        """Parses SSH log data and returns a list of SSHEventData.

        Args:
          data (str): Content of authentication log file.
          log_filename (str): Name of the log file whose content is read.
          log_year (int): SSH authentication log year.

        Returns:
          List(SSHEventData): Returns SSH events as list of SSHEventData.
        """
        # check valid year is provided
        # If valid year isn't provided raise error
        if not log_year:
            current_date = datetime.now()
            log_year = current_date.year
            log.warning(
                "Log year not provided in %s - assuming log year as %d",
                log_filename,
                log_year,
            )

        if log_year:
            if log_year < self.MIN_LOG_YEAR or log_year > self.MAX_LOG_YEAR:
                raise Exception(
                    f"Log year {log_year} is outside of acceptable range"
                    f" in {log_filename}"
                )

        ssh_records = []

        sshd_message_type_re = re.compile(r".*sshd\[\d+\]:\s+([^\s]+)\s+([^\s]+)\s.*")

        sshd_message_type = None
        # Only processing authentication logs with pattern sshd[9820]
        for line in re.findall(r".*sshd\[\d+\].*", data):
            try:
                sshd_message_type = sshd_message_type_re.search(line).group(1)
            except AttributeError:
                # NOTE: This does not mean actual error. This means the syslog event
                # is not interesting for us to process for authentication analysis.
                # example: Preauth disconnection events.
                log.error("Unable to get SSH message type: %s", line)
                continue

            if not sshd_message_type:
                log.debug("SSH message type not set")
                continue

            for key, value in self.MESSAGE_GRAMMAR.items():
                if key.lower() == sshd_message_type.lower():
                    try:
                        parsed_ssh_event = value.parseString(line)

                        # handle date/time
                        dt_object = self.parse_message_datetime(
                            parsed_ssh_event.datetime, log_year
                        )
                        if not dt_object:
                            log.error("Error extracting date/time from %s", line)
                            continue
                        event_date = dt_object.strftime("%Y-%m-%d")
                        event_time = dt_object.strftime("%H:%M:%S")
                        event_timestamp = dt_object.timestamp()

                        # event_type and auth_result
                        if key.lower() == "accepted":
                            event_type = "authentication"
                            auth_result = "success"
                        elif key.lower() == "failed":
                            event_type = "authentication"
                            auth_result = "failure"
                        elif key.lower() == "disconnected":
                            event_type = "disconnection"
                            auth_result = ""
                        else:
                            event_type = "unknown"
                            auth_result = ""

                        ssh_event_data = SSHEventData(
                            timestamp=event_timestamp,
                            date=event_date,
                            time=event_time,
                            hostname=parsed_ssh_event.hostname,
                            pid=parsed_ssh_event.pid,
                            event_key=event_type,
                            event_type=event_type,
                            auth_method=parsed_ssh_event.auth_method,
                            auth_result=auth_result,
                            username=parsed_ssh_event.username,
                            source_hostname="",
                            source_ip=parsed_ssh_event.source_ip,
                            source_port=parsed_ssh_event.source_port,
                        )
                        ssh_event_data.calculate_session_id()

                        ssh_records.append(ssh_event_data)
                    except pyparsing.ParseException as e:
                        log.debug("Pyparsing parsing exception: %s", {str(e)})
                        continue

        log.info("Total number of SSH records %d in %s", len(ssh_records), log_filename)
        return ssh_records

    def get_priority_value(self, priority_string: str) -> Priority:
        """Returns priority value.

        Args:
          priority_string (str): Priority values as string e.g. HIGH, MEDIUM, LOW

        Returns:
          Priority: Returns priority value of priority_string.
        """
        analyzer_priority_string = priority_string.upper()

        try:
            return Priority[analyzer_priority_string]
        except KeyError:
            log.error(
                "Priority %s does not exist. Returning LOW", analyzer_priority_string
            )
            return Priority.LOW

    def brute_force_analysis(self, df: pd.DataFrame) -> Tuple[Priority, str, str]:
        """Runs brute force analysis.

        Args:
          df (pd.DataFrame): Pandas dataframe of SSH events.

        Returns:
          Tuple[Priority, str, str]: Returns brute force analysis result as tuple.
            Priority: Priority of the findings.
            str: Brief summary of the findings.
            str: Detailed information as markdown.
        """
        bfa = BruteForceAnalyzer()

        try:
            bfa_result = bfa.run(df)
            if not bfa_result:
                return (
                    Priority.LOW,
                    "No findings for brute force analysis",
                    "##### Brute force analysis\n\n- No findings",
                )
            result_priority = bfa_result.result_priority
            result_summary = bfa_result.result_summary
            result_markdown = bfa_result.result_markdown

            priority = self.get_priority_value(result_priority)

            if not result_summary:
                result_summary = "No findings for brute force analysis"
            if not result_markdown:
                result_markdown = "##### Brute Force Analysis\n\n- No findings"

            return (priority, result_summary, result_markdown)
        except Exception as exception:
            log.error("Unable to run brute force analyzer. %s", str(exception))
            return (Priority.LOW, "", "")
