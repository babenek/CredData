import json
import os
import subprocess
from pathlib import Path

from benchmark.common.constants import URL, ScannerType
from benchmark.scanner.scanner import Scanner


class Gitleaks(Scanner):
    rule_matcher = {
        "generic-api-key": "generic-api-key",
        "private-key": "PEM Private Key",
        "jwt": "JSON Web Token",

        "aws-access-token": "aws-access-token",

        "curl-auth-header": "curl-auth-header",
        "curl-auth-user": "curl-auth-user",
        "dropbox-api-token": "dropbox-api-token",
        "facebook-secret": "facebook-secret",
        "gcp-api-key": "gcp-api-key",
        "grafana-api-key": "grafana-api-key",
        "hashicorp-tf-password": "hashicorp-tf-password",

        "kubernetes-secret-yaml": "kubernetes-secret-yaml",
        "linkedin-client-id": "linkedin-client-id",
        "linkedin-client-secret": "linkedin-client-secret",

        "stripe-access-token": "stripe-access-token",
        "twitch-api-token": "twitch-api-token",
        "twitter-api-key": "twitter-api-key",
        "twitter-api-secret": "twitter-api-secret",
        "vault-service-token": "vault-service-token",
    }


    def __init__(self, working_dir, cred_data_dir, preload: bool, fix: bool):
        super().__init__(ScannerType.GITLEAKS, URL.GITLEAKS, working_dir, cred_data_dir, preload, fix)
        self.output_dir: str = f"{self.scanner_dir}/output.json"

    @property
    def output_dir(self) -> str:
        return self._output_dir

    @output_dir.setter
    def output_dir(self, output_dir: str) -> None:
        self._output_dir = output_dir

    def init_scanner(self) -> None:
        self.gitleaks_path = f"{os.path.dirname(os.path.realpath(__file__))}/bin/gitleaks/gitleaks"

    def run_scanner(self) -> None:
        self.init_scanner()
        subprocess.call([self.gitleaks_path, "dir", f"{self.cred_data_dir}/data", "-f", "json", "-r", self.output_dir],
                        cwd=self.scanner_dir)

    def parse_result(self) -> None:
        with open(self.output_dir, "r") as f:
            data = json.load(f)

        for line_data in data:
            path = Path(line_data["File"])
            assert path.parts.count("data") == 1, f"Only one 'data' dir must be in path:{path}"
            for n, i in enumerate(path.parts):
                if "data" == i:
                    path = '/'.join([str(x) for x in path.parts[n:]])
                    break
            path_upper=str(path).upper()
            if any(i in path_upper for i in ["/COPYING", "/LICENSE"]):
                continue
            rule=Gitleaks.rule_matcher.get(line_data["RuleID"], "Other")
            start_value = line_data["StartColumn"] - 2
            if 0 > start_value:
                start_value = 0
            offset = line_data["Match"].find(line_data["Secret"])
            if 0 < offset:
                start_value += offset
            self.check_line_from_meta(str(path),
                                      line_data["StartLine"],
                                      line_data["EndLine"],
                                      start_value,
                                      -1,
                                      rule,
                                      )
