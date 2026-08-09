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

## Evidence file permissions

Evidence refreshes reject symlinked targets and multi-link files, stage each generated artifact as owner-read/write only (`0600`), fsync it, and atomically replace the managed target. Committed evidence is intentionally public synthetic data and may be checked out with ordinary repository permissions; this pipeline must not be used for secrets or private inputs.

## Pack/index closed subset

The baseline pack experiment passes only three fixed synthetic blob IDs to `git pack-objects`. The separate OFS experiment passes two fixed 77,824-byte synthetic blob IDs and fixed single-threaded delta options. Neither accepts a repository path, revision, ref, caller-provided object list, or caller-selected optimizer settings. Generated `.pack` and `.idx` files must be regular, single-link files no larger than 1 MiB and must remain the same inode and size across the bounded read.

The independent parser accepts pack v2 and index v2 with logical commit, tree, and blob entries only; tag entries are outside this closed subset. Its bounded OFS_DELTA subset requires an exact earlier pack-entry base, canonical biased offsets and size headers, no more than depth 4 or 4,096 instructions, at most three bytes for bounded offsets and sizes, at most 256 KiB per object or delta program, and at most 16 MiB of aggregate expanded output. It rejects REF_DELTA and thin packs, more than 64 objects, invalid or unterminated zlib streams, duplicate logical objects, non-canonical fanout/large-offset tables, and any mismatch among logical object IDs, CRC32 rows, offsets, pack trailer, index pack binding, or index checksum. The OFS runtime additionally requires exactly one full blob, one depth-one OFS entry, an exact re-encoding of the observed biased distance, and a complete fixed logical inventory. Its report records normalized pack arguments and an exact stdin digest; output bytes are only expected to repeat under the same Git build. These checks establish bounded fixture storage integrity; they do not establish provenance, authenticity, repository reachability, collision resistance, or safety of arbitrary Git data.

## SHA-1 scope

The lab uses SHA-1 because the scenario explicitly models a SHA-1 Git object database. The independent envelope calculation demonstrates deterministic content addressing and detects accidental changes in these fixtures. It is not a signature, authentication mechanism, or claim of modern collision resistance.

## Reporting an issue

Please open a GitHub issue with a minimal reproduction. Do not include credentials, private repository contents, environment dumps, or personal data.
