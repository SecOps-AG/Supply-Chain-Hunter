"""Attack families and the subtype choices that belong to each family."""

from __future__ import annotations

FAMILY_CRITERIA = {
    "none": "No attack behavior was added in this release.",
    "obfuscated_loader": "Code is decoded, unpacked, or decrypted and then executed.",
    "install_hook": "A lifecycle script, setup command, or install hook runs the added behavior.",
    "dependency_abuse": "A new or swapped dependency is unrelated to the package and carries the behavior.",
    "credential_theft": "Added behavior reads tokens, keys, or session material.",
    "persistence": "Added behavior keeps running after install via startup files or a scheduler.",
    "remote_payload": "Added behavior fetches remote code or a binary and executes it.",
    "wormlike_spread": "Added behavior tries to publish further packages or infect other local projects.",
    "other": "Hostile behavior that does not match a named family.",
}

SUBTYPES: dict[str, dict[str, str]] = {
    "obfuscated_loader": {
        "base64_exec": "Decodes base64 or a similar encoding and then executes it.",
        "packed_string": "Builds code from concatenated, reversed, or hex-escaped strings.",
        "foreign_interpreter": "Launches another interpreter on a decoded payload.",
    },
    "install_hook": {
        "lifecycle_script": "An npm or packaging lifecycle script runs the behavior.",
        "setup_cmdclass": "A setuptools cmdclass or install override runs the behavior.",
        "binary_postinstall": "A compiled or downloaded binary runs at install.",
    },
    "dependency_abuse": {
        "new_unrelated": "Adds a dependency unrelated to the package purpose.",
        "version_pin_swap": "Swaps a dependency to an unexpected name or version.",
        "git_or_url_dep": "Points a dependency at a URL or a git repository.",
    },
    "credential_theft": {
        "env_tokens": "Reads environment variables that hold tokens or secrets.",
        "cloud_keys": "Reads cloud provider credential files or metadata credentials.",
        "ssh_material": "Reads SSH private keys or agent sockets.",
        "browser_stores": "Reads browser cookie or password stores.",
    },
    "persistence": {
        "cron_or_startup": "Adds a cron job, launch agent, or other startup hook.",
        "shell_rc": "Edits a shell rc or profile file.",
        "ssh_authorized": "Writes SSH authorized_keys or a similar trust file.",
    },
    "remote_payload": {
        "http_download_exec": "Downloads a payload over HTTP and runs it.",
        "raw_ip_callback": "Contacts a raw IP address.",
        "dns_or_paste": "Fetches code from a paste site or from DNS text.",
    },
    "wormlike_spread": {
        "republish": "Attempts to publish further packages.",
        "token_reuse": "Uses a stolen publish token to spread.",
        "dependency_injection": "Writes itself into other local projects.",
    },
    "other": {
        "unspecified": "Behavior does not match a named subtype.",
        "mixed": "Several hostile behaviors are present, and no single named subtype covers them.",
    },
    "none": {},
}

# Second speculative request only when a family's probability clears this bar.
FAMILY_FLOOR = 0.15


def winning_families(probabilities: dict[str, float], choice: str) -> list[str]:
    """Top one or two families that have subtype questions. Hierarchical: not every family."""
    ranked = sorted(
        ((name, float(prob)) for name, prob in probabilities.items() if name != "none"),
        key=lambda item: item[1],
        reverse=True,
    )
    picked = [name for name, prob in ranked if prob >= FAMILY_FLOOR][:2]
    if not picked and choice not in (None, "", "none"):
        picked = [choice]
    return [name for name in picked if SUBTYPES.get(name)]
