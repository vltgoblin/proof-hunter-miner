"""Build a self-contained, checksum-bound launcher bundle. No network or wallet I/O."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parent
TARGETS = {"linux-x86_64", "linux-aarch64", "macos-aarch64", "macos-x86_64", "windows-x86_64"}

def package(binary, target, output):
    if target not in TARGETS:
        raise ValueError("Unsupported release target")
    contents = Path(binary).read_bytes()
    if not contents:
        raise ValueError("Empty binary")
    profile = json.loads((ROOT / "profiles/mainnet.json").read_text())
    if profile.get("chainId") != 4663 or profile.get("network") != "mainnet":
        raise ValueError("Mainnet profile must use chain 4663")
    for key in ("coreCodeSha256", "basketCodeSha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", profile.get(key, "")):
            raise ValueError("Missing deployed code checksum")
    profile.update(ready=True, reason="Packaged with the matching release binary.", binarySha256=hashlib.sha256(contents).hexdigest())
    name = "bproof.exe" if target.startswith("windows") else "bproof"
    entries = {name: contents, "profiles/mainnet.json": (json.dumps(profile, indent=2)+"\n").encode()}
    for source, destination in [(ROOT/"proof-hunters", "proof-hunters"), (ROOT/"profiles/testnet.json", "profiles/testnet.json"), (ROOT/"README.md", "README.md"), (ROOT.parent/"LICENSE", "LICENSE"), (ROOT.parent/"agent-skills/proof-hunters-mining/SKILL.md", "agent-skills/proof-hunters-mining/SKILL.md")]:
        entries[destination] = source.read_bytes()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, content in sorted(entries.items()):
            entry = zipfile.ZipInfo("proof-hunters/" + path, date_time=(2026, 9, 23, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (0o100755 if path in (name, "proof-hunters") else 0o100644) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, content)
    return profile

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    package(args.binary, args.target, args.output)
