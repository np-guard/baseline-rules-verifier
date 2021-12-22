# k8s-netpol-verify

This Task checks the connectivity in a given Kubernetes cluster against a set of corporate policies. It will first extract the cluster's connectivity graph by scanning your repository for YAML files containing endpoint resources (e.g., Deployments) or connectivity resources (Kubernetes NetworkPolicies). It will then verify that the connectivity graph adheres to a set of corporate policies, given as the Task's input. Corporate policies are defined in YAML files; their syntax is defined [here](https://github.com/shift-left-netconfig/baseline-rules).

This Task is part of a wider attempt to provide [shift-left automation for generating and maintaining Kubernetes Network Policies](https://shift-left-netconfig.github.io/).


## Install the Task

```
kubectl apply -f https://raw.githubusercontent.com/shift-left-netconfig/baseline-rules-verifier/master/tekton/netpol-verify-task.yaml
```

## Parameters
* **corporate-policies**: An array of corporate policy files to check against (either as GitHub URLs or as paths under workspace).
* **deployment-path**: The path in the 'source' workspace where deployment yamls are.  (_default:_ `.`)
* **netpol-path**: The path in the 'source' workspace where the NetworkPolicy yamls are stored (_default:_ `.`)
* **output-format**: The format in which to output verifitaion results (either "md" or "txt") (_default:_ `md`)
* **output-dir**: The directory under 'source' workspace to write results file into (_default:_ `netpol-verify-output-dir`)

## Workspaces
* **source**: A [Workspace](https://github.com/tektoncd/pipeline/blob/main/docs/workspaces.md) containing the application YAMLs to analyze.

## Platforms

The Task can be run on `linux/amd64`.

## Usage

This TaskRun runs the Task to verify the connectivity of a previously checked-out app against two corporate policies.

```yaml
apiVersion: tekton.dev/v1beta1
kind: TaskRun
metadata:
  name: verify-my-netpols
spec:
  taskRef:
    name: k8s-netpol-verify
  params:
  - name: corporate-policies
    value:
    - https://github.com/shift-left-netconfig/baseline-rules/blob/master/examples/restrict_access_to_payment.yaml
    - https://github.com/shift-left-netconfig/baseline-rules/blob/master/examples/ciso_denied_ports.yaml
  workspaces:
  - name: source
    persistentVolumeClaim:
      claimName: my-source
```

For a more complete example, see [this PipelineRun](netpol-verify-plr.yaml).
