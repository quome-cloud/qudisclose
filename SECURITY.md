# Security policy

qudisclose is itself a disclosure system. Vulnerabilities **in qudisclose** are accepted machine-to-machine
through the project's own intake MCP server once deployed (see README → "Reporter side"), or, until then, as a
GitHub private vulnerability report on this repository.

Defaults this project ships with:

- Acknowledgement is immediate and automatic (SLO 15 min).
- Embargo is at most 7 days and ends when a fix is published.
- Reporters are credited unless they opt out.
- No bounty.

## The local sandbox is not a boundary against a hostile test

The default `local` sandbox backend (isolation class `process`) is a development convenience. A reproduction test
runs there as the platform's own user: the network is cut and the environment is scrubbed, cases do not share the
repository's `.git`, and on macOS the repository is read-only to the case, but the test can still read whatever
that user can read (including the `keys/` directory) and write outside the repository. Do not run the local backend
on submissions from parties you do not trust. An intake that accepts them needs the `quome` backend (class `vm`).
Every receipt names the backend and what it enforced.

See `docs/nsa-mcp-controls.md` for the security architecture.
