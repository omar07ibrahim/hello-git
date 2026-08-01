# Git DAG Evidence Lab

> A dependency-free Python systems lab that constructs a real Git object database from plumbing commands and independently verifies every byte-addressed object.

The experiment demonstrates a subtle but important property: a merge commit and a rebase-shaped replay can resolve to **exactly the same tree** while preserving **different histories**.

![Real offline Git DAG evidence report showing the verified graph, checks, CLI receipt, and object envelope](docs/assets/git-dag-report.png)

<p align="center"><sub>Attested 1440×1800 Chromium capture of the checked-in offline report. No external assets, JavaScript, network, secrets, or host-repository data.</sub></p>

## Quick start

Requirements: Python 3.10+ and Git 2.29+. There are no runtime Python dependencies.

```bash
python3 -m git_dag_lab verify
python3 -m git_dag_lab inspect
python3 -m unittest discover -s tests -v
```

The first command creates a private temporary bare repository, builds 14 objects, verifies the graph, prints one receipt, and removes the repository:

![Exact verified CLI transcript for Git DAG Evidence Lab](docs/assets/git-dag-cli.svg)

```text
PASS git-dag-lab/v1 objects=14 commits=5 same_tree=true different_history=true receipt_sha256=2da1ccd8799699ade939f3901566e448baeb9691973624452231b35594469c84
```

## What the lab actually builds

The fixture contains three blobs, six trees, and five commits. `merge` stores the ordered parents `[feature, docs]`; `replay` stores only `[docs]`. Their tree IDs match, their commit IDs differ, and neither result commit is an ancestor of the other.

![Actual five-commit Git topology with real abbreviated object IDs and backward parent arrows](docs/assets/git-dag-topology.svg)

The replay is called **rebase-shaped** because it is constructed directly with `git commit-tree`. The lab does not claim to execute porcelain `git rebase`.

## The hard part: verify Git without trusting Git

Writing an object with Git and asking Git to identify it would only prove that Git agrees with itself. This lab reads the raw stored bytes and independently computes:

```text
SHA-1("type" + SPACE + decimal_size + NUL + payload)
```

It repeats that calculation for all 14 objects, parses binary tree records, checks Git's directory-aware ordering, parses ordered commit parents, verifies exact refs and reachability, runs strict `git fsck`, and tests the complete ancestry matrix.

![Actual merge commit bytes, Git object header, and independently reconstructed object ID](docs/assets/git-object-envelope.svg)

SHA-1 is used because this scenario models a SHA-1 Git object database. Here it demonstrates deterministic content addressing and fixture integrity; it is **not** presented as collision-resistant authentication, a signature, or a security token.

## Isolation and execution boundaries

- Git is resolved once to an absolute executable and invoked with argument arrays, never a shell.
- 10 local subcommands are allow-listed, while one fixed isolated `git init` creates the bare database; transport commands and remote-looking arguments are rejected.
- `HOME`, `XDG_CONFIG_HOME`, and `TMPDIR` are private; inherited Git config, hooks, replacement objects, identity, and object-directory redirects are ignored.
- fixed synthetic identity `dag-lab@example.invalid`, fixed UTC timestamps, and fixed LF payloads make object IDs reproducible.
- symlinked workspace components are rejected; stdout/stderr are spooled privately and checked before bounded reads.
- the host repository is never inspected by the experiment.

See [SECURITY.md](SECURITY.md) for the threat model and trusted-input boundary.

## Evidence pipeline

Every README visual begins with the same canonical CLI document. The generator runs fresh experiments twice, requires byte-identical outputs, derives the SVG and offline HTML, and binds each artifact into a hash manifest. Digest-pinned Chromium then captures the report in a read-only container with `--network none`. A separate attestation binds the exact report, rendered DOM, PNG, browser binary/version, container digest, isolation policy, viewport, and capture-script hash; without that attestation, the generator refuses to call the screenshot verified.

![Architecture of the fixed scenario, real Git plumbing, independent verification, and evidence publication pipeline](docs/assets/evidence-pipeline.svg)

### Reproduce the checked-in evidence

```bash
# Verify JSON, transcripts, SVGs, HTML, source hashes, and the existing PNG.
python3 -B tools/generate_evidence.py --check

# Rebuild evidence and recapture the report with the pinned browser container.
tools/capture_report.sh

# Run all engine, boundary, CLI, evidence, and provenance tests.
python3 -W error -m unittest discover -s tests -v
```

Current verified baseline: **61 tests**, **9/9 graph invariants**, **57 isolated Git invocations**, report receipt `2da1ccd8…69c84`, and screenshot SHA-256 `e539db11…e17e`.

| Artifact | What it proves |
|---|---|
| [`evidence/git-dag-v1.json`](evidence/git-dag-v1.json) | Canonical compact report, all objects, refs, checks, raw envelope proof, and receipt |
| [`verify.txt`](docs/demo/git-dag-v1/verify.txt) | Exact stdout from the real `verify` command; exit `0`, empty stderr |
| [`inspect.json`](docs/demo/git-dag-v1/inspect.json) | Human-readable output from the real `inspect` command |
| [`report.html`](docs/demo/git-dag-v1/report.html) | Dependency-free offline report used for the browser capture |
| [`rendered-dom.html`](docs/demo/git-dag-v1/rendered-dom.html) | Actual DOM emitted by Chromium during the attested capture |
| [`capture-attestation.json`](docs/demo/git-dag-v1/capture-attestation.json) | Report/DOM/PNG hashes plus verified browser, container, isolation, viewport, and script provenance |
| [`manifest.json`](docs/demo/git-dag-v1/manifest.json) | SHA-256, byte size, role, source hashes, normalized argv, and attestation receipt |
| [`git-dag-report.png`](docs/assets/git-dag-report.png) | Actual Chromium rendering of the report at 1440×1800 |

## Test coverage by risk

The standard-library suite exercises more than happy-path graph construction:

- independent blob, tree, and commit envelope hashes;
- exact object/ref inventories, parent ordering, reachability, and ancestry;
- Git's special `directory/` tree ordering, truncated binary objects, and malformed headers;
- hostile inherited Git environment and fake global identity/config;
- symlinked and NUL-containing roots, subprocess timeouts, output limits, and sanitized failures;
- concurrent deterministic runs, temporary cleanup, and immutable report/receipt binding;
- byte-identical evidence regeneration, visual receipt binding, PNG dimensions, source hashes, CSP, and secret/host marker rejection.

## Project history

This repository began as Omar Ibrahim's AI1030 Git exercise. The three original files are preserved byte-for-byte in [`docs/history`](docs/history/) while the repository evolves through reviewable portfolio-grade commits.

## License

No license has been granted for this repository.
