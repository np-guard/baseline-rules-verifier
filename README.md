# baseline-rules-verifier
This application verifies the connectivity in a given Kubernetes cluster
(as defined by its NetworkPolicy resources) against a set of baseline rules.

### Requirements:

* Python 3.7 or above
* An installation of [NCA](https://github.com/IBM/network-config-analyzer)

### Installation:
```commandline
git clone --recurse-submodules https://github.com/shift-left-netconfig/baseline-rules-verifier.git
cd baseline-rules-verifier
python3 -m venv venv
source venv/bin/activate  # the exact script may depend on the shell you are using
pip install -r requirements.txt
```

### Usage:
```
python src/baseline_verify.py -r <repo> -b <baseline_rules_file1> [-b <baseline_rules_file2> ...] <networkpolicy_file>
```
* `repo` is a path or url to the repository where deployments are defined 
* `baseline_rules_file` is a yaml file containing a list of baseline rules. See [file format definition](https://github.com/shift-left-netconfig/baseline-rules#baseline-rules) and [these examples](https://github.com/shift-left-netconfig/baseline-rules/tree/master/examples)
* `networkpolicy_file` is a yaml file with Kubernetes NetworkPolicies to verify

**For example:**
```commandline
python src/baseline_verify.py -b baseline-rules/examples/allow_access_to_google.yaml -r https://github.com/GoogleCloudPlatform/microservices-demo/tree/master/release tests/netpols/microservices-netpols.yaml
```

**More command-line switches:**
* `--out_file <out_file>` - dump all output to `out_file`
* `--pr_url <url>` - add a PR comment with verification output, using the given API url
* `--format <text_format>` - Use the given text_format to format output. Supported formats are "txt" and "md"
* `--ghe_token <token>` - Use the given token to access GitHub repos
* `--nca_path <nca_path>` - Specify the path to where [Network-Config-Analyzer](https://github.com/IBM/network-config-analyzer) is installed
