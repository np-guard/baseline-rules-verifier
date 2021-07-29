FROM ghcr.io/shift-left-netconfig/nca:1.0

COPY src/ /baseline-rules-verifier/src/
COPY baseline-rules/ /baseline-rules-verifier/baseline-rules/

ENTRYPOINT ["python", "/baseline-rules-verifier/src/baseline_verify.py"]
