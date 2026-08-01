# Git DAG Evidence Lab

A dependency-free Python laboratory that constructs a real Git object database from plumbing commands, then verifies every object independently. The central experiment proves a subtle systems property: a merge commit and a rebase-shaped replay can resolve to exactly the same tree while retaining different histories.

This repository began as Omar Ibrahim's AI1030 Git exercise. The original learning materials are preserved in [`docs/history`](docs/history/) while the project evolves in reviewable increments.

## Run the experiment

Requirements: Python 3.10+ and Git 2.29+.

```bash
python3 -m git_dag_lab verify
python3 -m git_dag_lab inspect
python3 -m unittest discover -s tests -v
```

The lab creates three blobs, six trees, and five commits in an isolated bare SHA-1 object database. It publishes four temporary refs, runs strict `git fsck`, validates reachability and ancestry, and recomputes every object ID from the raw `type + size + NUL + payload` envelope.

## Scenario

```text
                  feature ───────┐
                 /                v
root ───────────<               merge       (combined tree)
                 \                ^
                  docs ──────────┘
                    \
                     replay                   (same combined tree)
```

`merge` has the ordered parents `[feature, docs]`; `replay` has only `[docs]`. Their tree IDs match, their commit IDs differ, and neither result commit is an ancestor of the other. The replay is called **rebase-shaped** because the object is created directly with `git commit-tree`; the lab does not claim to run porcelain `git rebase`.

## Trust boundaries

- no third-party Python dependency or network operation;
- no shell command construction or arbitrary Git subcommand passthrough;
- no read of the host repository, global Git config, or host identity;
- fixed synthetic `dag-lab@example.invalid` identity and UTC timestamps;
- canonical, path-free, version-free JSON with a SHA-256 receipt;
- temporary workspace cleanup on success and failure.

See [`SECURITY.md`](SECURITY.md) for the full threat model and the exact SHA-1 non-claim.

## Development status

The deterministic engine and its boundary tests are the first portfolio-grade increment. Reproducible evidence, actual CLI captures, an offline report, generated architecture diagrams, and a real browser screenshot follow in the next commit on this branch.

## License

No license has been granted for this repository.
