FROM python:3.8-slim

RUN python -m pip install -U pip wheel setuptools
COPY requirements.txt .
RUN pip install -r ./requirements.txt

RUN apt-get update && apt-get install curl -y

RUN curl -L "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" --output /usr/local/bin/kubectl
RUN chmod +x /usr/local/bin/kubectl

RUN curl -L https://github.com/projectcalico/calicoctl/releases/download/v3.3.1/calicoctl --output /usr/local/bin/calicoctl
RUN chmod +x /usr/local/bin/calicoctl

COPY src/ /baseline-rules-verifier/src/
COPY baseline-rules/ /baseline-rules-verifier/baseline-rules/

ENTRYPOINT ["python", "/baseline-rules-verifier/src/baseline_verify.py"]
