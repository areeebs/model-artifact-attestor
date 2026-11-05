from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify(manifest: dict[str, Any], root: Path) -> dict[str, Any]:
    items = manifest.get("artifacts")
    if not isinstance(items, list):
        raise ValueError("Manifest must contain an artifacts list.")
    root = root.resolve(strict=True)
    findings: list[dict[str, str]] = []
    verified = 0
    for index, item in enumerate(items):
        subject = str(item.get("path", index)) if isinstance(item, dict) else str(index)
        if not isinstance(item, dict):
            findings.append({"severity": "error", "code": "invalid_artifact", "subject": subject})
            continue
        rel = Path(str(item.get("path", "")))
        if rel.is_absolute() or ".." in rel.parts:
            findings.append({"severity": "high", "code": "path_outside_root", "subject": subject})
            continue
        path = root / rel
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(root)
            if path.is_symlink() or not resolved.is_file():
                raise ValueError
        except (OSError, ValueError):
            findings.append({"severity": "high", "code": "unsafe_or_missing_path", "subject": subject})
            continue
        for field in ("source", "license", "format"):
            if not isinstance(item.get(field), str) or not item[field].strip():
                findings.append({"severity": "medium", "code": f"missing_{field}", "subject": subject})
        if item.get("scan_status") != "passed":
            findings.append({"severity": "high", "code": "no_passed_scan_attestation", "subject": subject})
        expected = item.get("sha256")
        if not isinstance(expected, str) or len(expected) != 64:
            findings.append({"severity": "error", "code": "invalid_sha256", "subject": subject})
            continue
        actual = sha256_file(resolved)
        if actual.lower() != expected.lower():
            findings.append({"severity": "critical", "code": "digest_mismatch", "subject": subject})
        else:
            verified += 1
    return {"artifacts_checked": len(items), "digests_verified": verified, "findings": findings,
            "pass": not any(x["severity"] in {"critical", "high", "error"} for x in findings)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a local artifact manifest without loading model files.")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args()
    try:
        data = json.loads(args.manifest.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Manifest must be a JSON object.")
        report = verify(data, args.root)
        print(json.dumps(report, indent=2))
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 2
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
