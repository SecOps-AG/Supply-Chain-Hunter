"""Offline Noul stand-ins used only to fit shipped prior weights.

Runtime classification never calls this module. It asks Jev and feeds those
probabilities to the logistic head. The stand-in exists so the prior can be
fit from the same fixture excerpts the tests mock.
"""

from __future__ import annotations

PASS_IDS = (
    "decode_then_run",
    "shell_child_process",
    "network",
    "credential_read",
    "persistence_path",
    "install_time_execution",
    "unrelated_new_dependency",
    "embedded_payload",
    "reviewer_instructions",
)

_CAPABILITY = {
    "cap_network": "network",
    "cap_process": "shell_child_process",
    "cap_credential": "credential_read",
    "cap_persist": "persistence_path",
    "cap_install_time": "install_time_execution",
}


def noul_values(excerpt: str) -> dict[str, float]:
    text = (excerpt or "").lower()

    def has(*needles: str) -> bool:
        return any(needle in text for needle in needles)

    decode = 0.94 if ("base64" in text and ("exec" in text or "eval" in text)) else 0.05
    shell = 0.91 if has("execsync", "child_process", "subprocess", "os.system", "check_call", "popen") else 0.05
    network = 0.86 if has("http://", "https://", "fetch(", "urlopen", "socket") else 0.04
    credential = 0.90 if has("npm_token", "id_rsa", ".ssh", "aws_secret", "aws_access", "github_token") else 0.04
    persist = 0.88 if has("crontab", ".bashrc", "launchagents", "authorized_keys") else 0.03
    install = 0.96 if has("postinstall", "preinstall", "cmdclass") else 0.05
    unrelated = 0.82 if has("palette-telemetry", "unrelated-logger") else 0.04
    embedded = 0.84 if "base64" in text else 0.04
    reviewer = 0.93 if has("ignore all findings", "you are a reviewer", "ignore previous") else 0.03
    stego = 0.04
    if "binary-or-media-file" in text and has("eval", "exec", "atob", "base64"):
        stego = 0.86
    encoded_import = 0.91 if has("require(atob", "import(atob", "require(buffer.from", "import(buffer.from") else 0.04
    values = {
        "decode_then_run": decode,
        "shell_child_process": shell,
        "network": network,
        "credential_read": credential,
        "persistence_path": persist,
        "install_time_execution": install,
        "unrelated_new_dependency": unrelated,
        "embedded_payload": embedded,
        "reviewer_instructions": reviewer,
        "steganography": stego,
        "encoded_dynamic_import": encoded_import,
    }
    for cap, source in _CAPABILITY.items():
        values[cap] = values[source]
    return values


def noul_for(key: str, excerpt: str) -> float:
    values = noul_values(excerpt)
    if key in values:
        return values[key]
    mapped = _CAPABILITY.get(key)
    if mapped:
        return values[mapped]
    return 0.05
