import os
import sys
import json

sys.path.insert(0, os.path.abspath("obfuscated"))

from app.integrity import generate_manifest

manifest = generate_manifest()

with open(
    r"obfuscated\integrity_manifest.json",
    "w",
    encoding="utf-8"
) as f:
    json.dump(manifest, f, indent=2)

print("Manifest generated successfully.")