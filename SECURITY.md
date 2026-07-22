# Security Policy

PickBits Dependency Audit processes untrusted manifests, lockfiles, advisory data, and report strings. Security bugs in those paths are treated as high priority.

## Report a vulnerability

Please use GitHub's private vulnerability reporting flow for this repository rather than opening a public issue. If private reporting is not yet enabled, open a minimal issue asking the maintainers for a private contact channel and do not include vulnerability details. Include privately:

- the affected release or commit;
- operating system and OSV-Scanner version;
- reproduction steps or a minimal hostile fixture;
- expected and observed behavior; and
- any evidence of code execution, path traversal, secret exposure, unsafe HTML rendering, or incorrect clean results.

Do not include real credentials, proprietary source code, or private dependency data in a report.

## High-priority classes

- command or prompt injection from a feed, advisory, manifest, or lockfile;
- execution of package-manager lifecycle scripts during a read-only scan;
- path traversal or report writes outside the selected report directory;
- unescaped package/advisory content in HTML output;
- source-code or credential upload not explicitly disclosed;
- signature or update-channel bypass;
- automated patching without explicit approval; and
- false `clean` status after a failed or unresolved data source.

## Scope boundaries

PickBits Dependency Audit is a dependency vulnerability tool. It does not scan arbitrary malware, running processes, network services, source-code vulnerabilities, secrets, or deployment configuration unless a future component explicitly says otherwise.

OSV-Scanner and the OSV service are separate upstream projects. Vulnerabilities in their code or service should also be reported through their official security channels.

## Supported versions

Until a stable standalone release exists, only the latest commit on the default branch is supported. Tagged preview releases receive fixes when practical, but users should update to the newest release before reporting a problem.
