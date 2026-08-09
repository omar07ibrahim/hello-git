# Security model

Git DAG Evidence Lab creates a temporary bare repository below the selected workspace for each DAG or pack experiment and removes it after the run. It does not inspect the repository that contains this source code.

The command boundary is deliberately narrow:

- Git is executed by absolute path with argument arrays, never through a shell.
- the executable selected by the caller's `PATH` is treated as trusted, then resolved once to an absolute path.
- Only local plumbing and inspection subcommands are allow-listed; no transport command is available.
- `HOME`, `XDG_CONFIG_HOME`, and `TMPDIR` point to private temporary directories.
- inherited Git configuration, object-directory redirects, identity, hooks, prompts, and replacement objects are ignored.
- fixed synthetic identity and timestamps make commit objects reproducible without exposing a host identity.
- temporary roots with symlinked path components are rejected.
- stdout and stderr are captured in private temporary files and rejected before loading into memory when either exceeds 1 MiB.

## Pack/index closed subset

The pack experiment passes only three fixed synthetic blob IDs to `git pack-objects`; it does not accept a repository path, revision, ref, or caller-provided object list. Generated `.pack` and `.idx` files must be regular, single-link files no larger than 1 MiB and must remain the same inode and size across the bounded read.

The independent parser accepts pack v2 and index v2 only. It rejects OFS/REF deltas, more than 64 objects, objects expanding beyond 256 KiB, invalid or unterminated zlib streams, duplicate logical objects, non-canonical fanout/large-offset tables, and any mismatch among logical object IDs, CRC32 rows, offsets, pack trailer, index pack binding, or index checksum. These checks establish the fixed fixture's storage integrity; they do not establish provenance, authenticity, repository reachability, or safety of arbitrary Git data.

## SHA-1 scope

The lab uses SHA-1 because the scenario explicitly models a SHA-1 Git object database. The independent envelope calculation demonstrates deterministic content addressing and detects accidental changes in these fixtures. It is not a signature, authentication mechanism, or claim of modern collision resistance.

## Reporting an issue

Please open a GitHub issue with a minimal reproduction. Do not include credentials, private repository contents, environment dumps, or personal data.
