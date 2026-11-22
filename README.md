# Pre-commit Hook

A [pre-commit](https://pre-commit.com/) hook that checks the dependencies
you are about to commit for known CVEs — every time a lockfile or manifest
changes. Open source, auditable, privacy-first — powered by the ValtersIT
CVE API.

> Part of the ValtersIT platform — CVE & Threat-IP data you can query or run yourself.
> Explore both API and scanners: https://www.valtersit.com/platform/
> Scanner plans & pricing: https://www.valtersit.com/cve/pricing/#scanners

## What it does

When a commit touches one of these files, the hook reads the pinned
package versions from it, submits them to the ValtersIT API as one scan, and
prints the CVEs that matched:

| File | Ecosystem |
|---|---|
| `requirements*.txt` (`name==version` lines) | Python / PyPI |
| `package-lock.json`, `npm-shrinkwrap.json` (v1, v2, v3) | npm |
| `Gemfile.lock` | RubyGems |
| `composer.lock` | Composer / Packagist |
| `packages.lock.json` | NuGet |
| `*.csproj`, `*.fsproj`, `*.vbproj` (exact `Version`) | NuGet |
| `packages.config` | NuGet |

Commits that don't touch any of them don't run the hook at all, so there
is no network call on an ordinary code commit.

By default the hook **reports and never blocks**. Add `--fail-on-cvss 7.0`
to block commits that introduce a dependency with a matched CVE of CVSS 7.0
or higher.

## Your data stays yours

- **What we receive:** package name and version only (e.g. `lodash
  4.17.15`), plus an opaque system identifier — a one-way hash of local
  machine signals (machine-id, disk UUID, CPU count) that cannot be reversed
  to any of them — so repeat scans from the same machine are recognised as
  the same system.
- **What we never receive:** your IP address, hostname, MAC address,
  repository name, branch, commit message, file paths, source code, or the
  contents of any file. Nothing outside of `name` + `version` (+ that
  opaque identifier) ever leaves the hook.
- **What it does not do:** it only reads the staged dependency files
  pre-commit passes to it, writes nothing, and installs nothing — it runs
  with your system Python and the standard library (`language: script`),
  no virtualenv, no `pip install`.
- **Audit it yourself.** This is open source — `run_scan.py`,
  `valtersit_client.py` and `.pre-commit-hooks.yaml`, ~800 lines total.

## Install

### 1. Confirm authorised use once

pre-commit runs hooks without an interactive terminal, so the
authorised-use confirmation is given once, beforehand:

```bash
git clone https://gitlab.com/valtersit/pre-commit-hook /tmp/valtersit-hook
python3 /tmp/valtersit-hook/run_scan.py --confirm
#   ... read the notice, type YES ...
```

The confirmation is stored in `~/.valtersit/consent.json` and is per user,
not per repository.

### 2. Set your API key

```bash
export VALTERSIT_API_KEY="vit_v1_your_key_here"   # e.g. in ~/.bashrc / ~/.zshrc
```

Get a key at [valtersit.com/cve/pricing](https://www.valtersit.com/cve/pricing/#scanners).
Without a key the hook prints a notice and lets the commit through.

### 3. Add the hook to `.pre-commit-config.yaml`

```yaml
repos:
  - repo: https://gitlab.com/valtersit/pre-commit-hook
    rev: main            # pin to a commit SHA - `pre-commit autoupdate` can bump it later
    hooks:
      - id: valtersit-cve-scan
```

```bash
pre-commit install
```

Requires Python 3.7+ on `PATH` as `python3` and pre-commit itself.

## Options

Pass them with `args:`:

```yaml
      - id: valtersit-cve-scan
        args: [--fail-on-cvss, "7.0", --include-dev]
```

| Option | Meaning |
|---|---|
| `--fail-on-cvss SCORE` | Block the commit if a matched CVE has CVSS ≥ SCORE |
| `--include-dev` | Also scan `devDependencies` / `packages-dev` |

To scan every dependency file in the repository on demand (not only the
staged ones):

```bash
pre-commit run valtersit-cve-scan --all-files
```

## Sample output

```
ValtersIT CVE scan (changed dependency files)............................Failed
- hook id: valtersit-cve-scan
- exit code: 1

[i] package-lock.json: 412 pinned package(s)
[+] Scan submitted. 412 component(s) sent for matching.

  CVE                Package                            Version        CVSS
  CVE-2020-8203      lodash                             4.17.15        7.4

  Details: https://www.valtersit.com/cve/<CVE-ID>/

[!] Matched CVE with CVSS 7.4 >= 7.0 - blocking the commit (--fail-on-cvss).
    Update the dependency, or commit with --no-verify if you must.
```

`--fail-on-cvss` relies on the `results[].cvss` field of the scan response;
if the API is unreachable or the key is rejected, the hook reports the
problem and lets the commit through rather than blocking your work.

## Authorised use only

Run this hook only on code you own, or for which you have explicit written
authorisation to assess. `run_scan.py --confirm` shows exactly this and
requires you to type `YES`:

```
------------------------------------------------------------------------------
 ValtersIT Scanner — Authorised Use Confirmation
------------------------------------------------------------------------------
 Run this tool ONLY against systems you own, or for which you have explicit
 written authorisation to assess.

 This scan sends only component name + version, plus an opaque system
 identifier (a one-way hash of local machine signals such as machine-id
 and disk UUID, so repeat scans are recognised as the same system), to
 the ValtersIT API — no IP address, hostname, MAC address, or file
 contents. See the Privacy Policy: https://www.valtersit.com/privacy

 Type YES to confirm you are authorised to scan this system and continue.
 Anything else aborts without scanning.
------------------------------------------------------------------------------
```

See `valtersit_client.py` (`require_consent`) for that gate.

Licensed under Apache-2.0 (see `LICENSE` and `NOTICE`); provided without
warranty of any kind. "ValtersIT" and the ValtersIT logo are trademarks of
Valters Capital, SIA and are not licensed for use.

## Questions or a bug?

Please **don't** open GitHub/GitLab issues — I don't monitor them.
Reach me through the contact form instead: https://www.valtersit.com/contacts/

Maintained by Hugo Valters
