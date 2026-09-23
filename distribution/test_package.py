import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from package_release import package

class PackageTests(unittest.TestCase):
    def test_bundle_binds_exact_binary_and_keeps_source_unapproved(self):
        for target, filename in [("linux-x86_64", "bproof"), ("windows-x86_64", "bproof.exe")]:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                binary = root/filename
                binary.write_bytes(b"fixture binary, never a real release")
                output = root/"bundle.zip"
                package(binary, target, output)
                with zipfile.ZipFile(output) as archive:
                    profile = json.loads(archive.read("proof-hunters/profiles/mainnet.json"))
                    self.assertTrue(profile["ready"])
                    self.assertEqual(profile["chainId"], 4663)
                    self.assertEqual(profile["binarySha256"], hashlib.sha256(archive.read("proof-hunters/"+filename)).hexdigest())
                    self.assertFalse(json.loads(archive.read("proof-hunters/profiles/testnet.json"))["ready"])
                source = json.loads((Path(__file__).parent/"profiles/mainnet.json").read_text())
                self.assertFalse(source["ready"])
                self.assertIsNone(source["binarySha256"])

    def test_rejects_empty_or_unsupported_package(self):
        with tempfile.TemporaryDirectory() as directory:
            binary=Path(directory)/"empty"
            binary.write_bytes(b"")
            for target in ("linux-x86_64", "unknown"):
                with self.assertRaises(ValueError):
                    package(binary, target, Path(directory)/"bundle.zip")
