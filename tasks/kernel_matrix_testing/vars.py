from typing import Literal, Dict

platforms_file = "test/new-e2e/system-probe/config/platforms.json"

Arch = Literal["x86_64", "arm64"]

arch_mapping: Dict[str, Arch] = {
    "amd64": "x86_64",
    "x86": "x86_64",
    "x86_64": "x86_64",
    "arm64": "arm64",
    "arm": "arm64",
    "aarch64": "arm64",
}

VMCONFIG = "vmconfig.json"
