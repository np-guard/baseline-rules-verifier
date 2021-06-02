# baseline-rules-verifier
This application verifies the connectivity in a given Kubernetes cluster
(as defined by its NetworkPolicy resources) against a set of baseline rules.

### Requirements:

* Python 3.7 or above

### Installation:
1. `git clone --recurse-submodules git@github.com:shift-left-netconfig/baseline-rules-verifier.git`
1. `cd baseline-rules-verifier`
1. `python3 -m venv venv`
1. `source venv/bin/activate.csh` (the exact script may depend on the shell you are using) 
1. `pip install -r requirements.txt`

### Usage:
```
python src/baseline_verify.py [-r repoistory] [-b baseline_rules_file] <networkpolicy_file>
```
* `repository` is a path or url to the repository where deployments are defined 
* `baseline_rules_file` is a yaml file containing a list of baseline rules. See [this example](baseline-rules/examples/ciso_denied_ports.yaml)
* 'networkpolicy_file' is a yaml file with Kubernetes NetworkPolicies to verify

For example:
```commandline
python src/baseline_verify.py -b baseline-rules/examples/allow_access_to_google.yaml -r https://github.com/GoogleCloudPlatform/microservices-demo/tree/master/release tests/netpols/microservices-netpols.yaml
```
