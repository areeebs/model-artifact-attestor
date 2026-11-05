# Contributing

Thanks for considering a contribution.

- Keep tools deterministic and local-first unless a change clearly requires otherwise.
- Use synthetic data. Never commit secrets, private prompts, customer traces, or real incident artifacts.
- Explain the security boundary and any new assumptions in the documentation.
- Add focused regression coverage for behavior changes.
- Run: python -m unittest discover -s tests -v
- Keep generated output free of credentials and unnecessary personal data.

Please open a focused issue before a large change so scope and threat model can be discussed.
