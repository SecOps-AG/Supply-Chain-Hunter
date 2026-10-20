# Security policy

## Reporting a vulnerability

Please report security problems in Supply Chain Hunter privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue for them.

Include what you found, how to reproduce it, and the version or commit you tested. You should get a reply within a few days.

## Scope

In scope: bugs in Hunter itself, for example a way for a malicious package to make Hunter execute code, write outside its working directories, leak API keys or webhook secrets, or suppress its own alert through prompt injection.

Out of scope: malicious packages that Hunter missed or flagged wrongly. Those are detection-quality issues; please open a regular issue with the package name and versions.

## Handling untrusted input

Hunter downloads package archives and reads them as text. It never installs or runs them. Parts of each diff are sent to the model providers you configure, so do not point Hunter at private registries unless those providers are approved for that code.
