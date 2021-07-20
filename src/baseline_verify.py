#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

"""
This module allows verifying a set of network policies against a set of baseline rules
"""

import argparse
import subprocess
import os
import sys
import json
from pathlib import Path
from urllib import request
import yaml

base_dir = Path(__file__).parent.resolve()
common_services_dir = (base_dir / '../baseline-rules/src').resolve()
sys.path.insert(0, str(common_services_dir))

from baseline_rule import BaselineRules, BaselineRuleAction


class NetpolVerifier:
    """
    The main class for verifying a cluster connectivity against baseline rules.
    Converts baseline rules to k8s NetworkPolicy and runs NCA to verify cluster connectivity.
    """
    def __init__(self, netpol_file, baseline_rules_file, repo):
        self.netpol_file = netpol_file
        self.baseline_rules = BaselineRules(baseline_rules_file)
        self.repo = repo

    def verify(self, pr_url):
        """
        This function is where the actual rule verification happens
        :param str pr_url: The URL of the PR into which the output should be sent as a comment (if None, send to stdout)
        :return: Number of violated rules
        :rtype: int
        """
        nca_path = Path(Path(__file__).parent.absolute(), '..', '..',
                        'network-config-analyzer', 'network-config-analyzer', 'nca.py')
        fixed_args = [sys.executable, nca_path, '--base_np_list', self.netpol_file, '--pod_list', self.repo,
                      '--ns_list', self.repo]

        num_violated_rules = 0
        output = ''
        for rule in self.baseline_rules:
            rule_filename = f'{rule.name}.yaml'
            with open(rule_filename, 'w') as baseline_file:
                yaml.dump(rule.to_netpol(), baseline_file)
            query = '--forbids' if rule.action == BaselineRuleAction.deny else '--permits'
            nca_args = fixed_args + [query, rule_filename]
            nca_run = subprocess.run(nca_args, capture_output=True, text=True, check=False)
            if nca_run.returncode == 0:
                output += f'\n:white_check_mark: rule **{rule.name}** is satisfied\n'
            else:
                output += f'\n:x: rule **{rule.name}** is violated\n<p><details><summary>Details</summary>'
                output += '\n'.join(str(nca_run.stdout).split('\n')[2:5]) + '\n</details></p>\n'
                num_violated_rules += 1
            os.remove(rule_filename)

        if num_violated_rules == 1:
            output += f'\n1 rule (out of {len(self.baseline_rules)}) is violated\n'
        elif num_violated_rules:
            output += f'\n{num_violated_rules} rules (out of {len(self.baseline_rules)}) are violated\n'
        else:
            output += '\nAll rules are satisfied\n'

        if pr_url:
            self.write_git_comment(pr_url, output)
        else:
            print(output)

        return num_violated_rules

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
    parser.add_argument('--baseline', '-b', type=open, metavar='FILE', action='append', required=True,
                        help='A baseline-rules file')
    parser.add_argument('--repo', '-r', type=str, metavar='REPOSITORY', required=True,
                        help="Repository with the app's deployments")
    parser.add_argument('--pr_url', type=str, help='The full api url for adding a PR comment')
    parser.add_argument('--ghe_token', '--gh_token', type=str, help='A valid token to access a GitHub repository')
    args = parser.parse_args(args)

    if args.ghe_token:
        os.environ['GHE_TOKEN'] = args.ghe_token

    return NetpolVerifier(args.netpol_file, args.baseline, args.repo).verify(args.pr_url)


if __name__ == "__main__":
    sys.exit(netpol_verify_main())
