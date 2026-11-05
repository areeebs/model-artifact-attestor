# Model Artifact Attestor

Verify local model artifact digests and provenance manifests before controlled ingestion.

A manifest verifier for local model and dataset files. It checks SHA-256 digests, path containment, license/source declarations, and an explicit scanner result. Symlinks and paths outside the selected artifact root fail closed. The verifier is useful as one step in a model-ingestion review; it does not deserialize, execute, or claim to safety-scan model files.

The sample manifest contains metadata only. Replace it with a locally generated manifest and never publish private model artifacts or credentials.

## Install and run

Requires Python 3.11 or newer. The tool uses only the standard library.

~~~sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
model-attest examples/input.json
~~~

Run the regression suite:

~~~sh
python -m unittest discover -s tests -v
~~~

## Design constraints

This project is a local, deterministic analysis component. It does not call a model, contact a provider, or make changes to external systems. Findings are evidence for review, not a guarantee that an application is safe.

## References

- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [Protect AI ModelScan](https://github.com/protectai/modelscan)

## License

MIT. See LICENSE.
