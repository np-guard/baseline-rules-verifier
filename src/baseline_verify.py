#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

"""
This module allows verifying a set of network policies against a set of baseline rules
"""

import argparse
import os
import sys
import json
from dataclasses import dataclass
from enum import Enum
from io import StringIO
from pathlib import Path
from urllib import request
import yaml
from nca import nca_cli


base_dir = Path(__file__).parent.resolve()
common_services_dir = (base_dir / '../baseline-rules/src').resolve()
sys.path.insert(0, str(common_services_dir))

from baseline_rule import BaselineRules, BaselineRuleAction  # noqa: E402


class RuleStatus(Enum):
    satisfied = 0
    violated = 1
    unchecked = 2


@dataclass
class RuleResults:
    rule_name: str   # The name of the rule
    rule_status: RuleStatus  # Whether the rule is valid, violated or not checked
    details: str     # A detailed explanation why rule is not valid

    def _to_plain_text(self):
        ret = f'Rule {self.rule_name} is {self.rule_status.name}\n'
        if self.details:
            ret += self.details + '\n'
        return ret

    def _to_md_format(self):
        ret = ':white_check_mark:' if self.rule_status == RuleStatus.satisfied else ':x:'
        ret += f'Rule **{self.rule_name}** is {self.rule_status.name}\n'
        if self.details:
            ret += '<p><details><summary>Details</summary>' + self.details + '\n</details></p>\n'
        return ret

    def to_str(self, text_format):
        """
        :param str text_format: How to format the result ("md" or "txt")
        :return: Rule result as text, formatted according to the text format
        :rtype: str
        """
        if text_format == 'md':
            return self._to_md_format()
        return self._to_plain_text()


class NetpolVerifier:
    """
    The main class for verifying a cluster connectivity against baseline rules.
    Converts baseline rules to k8s NetworkPolicy and runs NCA to verify cluster connectivity.
    """
    def __init__(self, netpol_file, baseline_rules_file, repo):
        self.netpol_file = netpol_file
        self.baseline_rules = BaselineRules(baseline_rules_file)
        self.repo = repo

    @staticmethod
    def _run_network_config_analyzer(nca_args, debug_mode):
        exception_msg = ''
        # redirecting NCA's stdout and stderr to buffers
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = new_stdout = StringIO()
        sys.stderr = new_stderr = StringIO()

        try:
            nca_run = nca_cli.nca_main(nca_args)
        except Exception as e:
            nca_run = 8  # nca_run > 3 indicates that the rule was not checked (query was not executed)
            exception_msg = str(e)

        # read nca's output values from the redirected stdout and stderr
        nca_stdout = new_stdout.getvalue()
        nca_stderr = new_stderr.getvalue()
        # stop redirecting stdout and stderr to the buffers
        sys.stdout = old_stdout
        sys.stderr = old_stderr

        if debug_mode is not None:
            details = nca_stdout + '\n' + nca_stderr
        elif nca_run != 0:
            if exception_msg:  # nca raised an exception
                details = exception_msg
            else:  # nca query result was 1 (rule is violated) or query was not executed (rule is not checked)
                topology_output_words = ['cluster has', 'unique endpoints', 'namespaces']
                nca_out = nca_stdout.split('\n')
                # Remove nca's output about cluster topology info to set details output
                if all(word in nca_out[1] for word in topology_output_words):
                    details = '\n\n'.join(nca_out[2:5])
                else:
                    details = '\n\n'.join(nca_out[1:4])
        else:
            details = ''
        return nca_run, details

    def verify(self, args):
        """
        This function is where the actual rule verification happens
        :param args: The command-line arguments
        :return: Number of violated rules
        :rtype: int
        """
        if not self.baseline_rules:
            print('No rules to check')
            return 0

        fixed_args = ['--base_np_list', self.netpol_file, '--pod_list', self.repo, '--ns_list', self.repo]

        rule_results = []
        for rule in self.baseline_rules:
            rule_filename = Path(args.tmp_dir, f'{rule.name}.yaml')
            with open(rule_filename, 'w') as baseline_file:
                policies_list = rule.to_global_netpol_calico()
                yaml.dump_all(policies_list, baseline_file)

            query = '--forbids' if rule.action == BaselineRuleAction.deny else '--permits'
            nca_run, details = \
                self._run_network_config_analyzer(fixed_args + [query, str(rule_filename.absolute())], args.debug)
            rule_status = RuleStatus.satisfied if nca_run == 0 else RuleStatus.unchecked if nca_run > 3\
                else RuleStatus.violated
            rule_results.append(RuleResults(rule.name, rule_status, details))
            os.remove(rule_filename)

        output = '\n'.join(rule_result.to_str(args.format) for rule_result in rule_results)
        num_violated_rules = len([rule_result for rule_result in rule_results
                                  if rule_result.rule_status == RuleStatus.violated])
        num_unchecked_rules = len([rule_result for rule_result in rule_results
                                   if rule_result.rule_status == RuleStatus.unchecked])
        if num_violated_rules == 1:
            output += f'\n1 rule (out of {len(self.baseline_rules)}) is violated\n'
        elif num_violated_rules:
            output += f'\n{num_violated_rules} rules (out of {len(self.baseline_rules)}) are violated\n'
        if num_unchecked_rules == 1:
            output += f'\n1 rule (out of {len(self.baseline_rules)}) is not checked\n'
        elif num_unchecked_rules:
            output += f'\n{num_unchecked_rules} rules (out of {len(self.baseline_rules)}) are not checked\n'
        if not num_violated_rules and not num_unchecked_rules:
            output += '\nAll rules are satisfied\n'

        if args.pr_url:
            self.write_git_comment(args.pr_url, output)
        if args.out_file:
            args.out_file.write(output)
        print(output)

        return num_violated_rules + num_unchecked_rules

    @staticmethod
    def write_git_comment(pr_url, comment_body):
        """
        Add a comment to a PR
        :param str pr_url: The URL of the PR into which the output should be sent as a comment
        :param str comment_body:
        :return: The code returned by the GitHub server (201 means OK)
        :rtype: int
        """
        if 'GHE_TOKEN' not in os.environ:
            print("ERROR: missing GHE_TOKEN")
            return 0

        headers = {'Authorization': 'token {0:s}'.format(os.environ['GHE_TOKEN'])}
        data = {'body': comment_body}
        req = request.Request(pr_url, headers=headers, data=json.dumps(data).encode('ascii'))
        with request.urlopen(req) as resp:
            if resp.status not in [200, 201]:
                print("request failed, status = ", resp.status, "URL:", pr_url, "message = ", resp.read())
            else:
                print("request succeeded, status = ", resp.status, "message = ", resp.read())

            return resp.status


def netpol_verify_main(args=None):
    """
    This is the main entry point to verifying policies against baseline rules
    :param args: Commandline arguments
    :return: Number of violated rules
    :rtype: int
    """
    parser = argparse.ArgumentParser(description='A verifier for K8s Network Policies')
    parser.add_argument('netpol_file', type=str, help='A yaml file containing k8s NetworkPolicy resources')
    parser.add_argument('--baseline', '-b', type=str, metavar='FILE', action='append', required=True,
                        help='A baseline-rules file')
    parser.add_argument('--repo', '-r', type=str, metavar='REPOSITORY', required=True,
                        help="Repository with the app's deployments")
    parser.add_argument('--pr_url', type=str, help='The full api url for adding a PR comment')
    parser.add_argument('--out_file', '-o', type=argparse.FileType('w'), help='A file to dump output into')
    parser.add_argument('--format', type=str, default='md', help='Output format ("md" or "txt")')
    parser.add_argument('--ghe_token', '--gh_token', type=str, help='A valid token to access a GitHub repository')
    parser.add_argument('--tmp_dir', type=str, default='/tmp',
                        help="A directory into which verifier's temporary files can be written")
    parser.add_argument('--debug', type=int, help="Set to 1 to print debug information")
    parser.add_argument('--return_0', action='store_true', help='Force a return value 0')
    args = parser.parse_args(args)

    if args.ghe_token:
        os.environ['GHE_TOKEN'] = args.ghe_token

    npv = NetpolVerifier(args.netpol_file, args.baseline, args.repo)
    ret_val = npv.verify(args)
    return 0 if args.return_0 else ret_val


if __name__ == "__main__":
    sys.exit(netpol_verify_main() > 0)
