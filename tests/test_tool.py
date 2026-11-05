import hashlib
import tempfile
import unittest
from pathlib import Path

from tool import verify


class AttestorTests(unittest.TestCase):
    def test_matching_digest_and_complete_metadata_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = root / "weights.bin"
            artifact.write_bytes(b"synthetic weights")
            report = verify({"artifacts": [{
                "path": "weights.bin", "sha256": hashlib.sha256(b"synthetic weights").hexdigest(),
                "source": "internal-build-42", "license": "Apache-2.0", "format": "safetensors",
                "scan_status": "passed",
            }]}, root)
        self.assertTrue(report["pass"])
        self.assertEqual(1, report["digests_verified"])

    def test_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            report = verify({"artifacts": [{"path": "../outside", "sha256": "0" * 64}]}, Path(temp))
        self.assertIn("path_outside_root", {x["code"] for x in report["findings"]})

    def test_digest_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "model.bin").write_bytes(b"real bytes")
            report = verify({"artifacts": [{
                "path": "model.bin", "sha256": "0" * 64, "source": "registry",
                "license": "MIT", "format": "safetensors", "scan_status": "passed",
            }]}, root)
        self.assertIn("digest_mismatch", {x["code"] for x in report["findings"]})


if __name__ == "__main__":
    unittest.main()
