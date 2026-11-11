# Security policy

## Supported versions

NetScan is a small, self-contained tool. Security fixes are issued for the
latest minor release.

| Version | Supported |
|---------|-----------|
| 2.2.x   | yes       |
| < 2.2   | no        |

## Reporting a vulnerability

Please do **not** open a public issue for a suspected vulnerability. Report it
privately through the repository host's security advisory feature (or the
maintainer contact listed in the project metadata), including:

- the NetScan version (`netscan --version`),
- your platform and Python version,
- a minimal reproduction, and
- the impact you believe it has.

You can expect an acknowledgement within a few working days and a coordinated
disclosure once a fix is ready. Please give us a reasonable window to release a
patch before publishing details.

## Scope

In scope:

- the scanner engine, CLI, exporters, configuration loader, diff and history
  modules;
- the self-contained HTML reports (for example, HTML or SVG injection);
- the authorised load-test engine, including any way to bypass its
  authorization, scope or rate limits.

Out of scope:

- scanning or load-testing systems without authorization;
- findings that require a compromised local account or physical access;
- denial of service caused by pointing the tool at a third party;
- vulnerabilities in `rich`, Python or the operating system.

## Safe harbour

We will not pursue legal action against researchers who act in good faith,
follow this policy, avoid privacy violations and service disruption, and give
us reasonable time to respond. Only test systems you own or are explicitly
authorised to test. See [docs/AUTHORIZED_USE.md](docs/AUTHORIZED_USE.md).
