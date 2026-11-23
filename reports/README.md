# Multi-platform scanning — acceptance report

This directory holds the reproducible acceptance material for the
multi-platform scanning feature: what was run, the real outputs,
and how each requirement is met.

Everything under `output/` was produced by `scripts/run.sh` on
the host shown at the bottom of this file. Re-running the script
regenerates it.

## What changed

Before, a scan only saw the files that build for the machine it
ran on:

- a file behind another platform's build constraint was never
  parsed, so the same repository produced different findings on
  different machines;
- a package that exists only on one platform was skipped
  entirely;
- a finding that exists on several platforms could only be
  re-discovered by running the scanner once per machine and
  merging reports by hand, and the merge lost which platforms
  were affected.

Now one run covers a target platform set:

1. Each platform is analyzed with its own build context, so
   mutually exclusive implementations are all analyzed.
2. Findings that occur on several platforms are merged into one
   issue carrying the list of platforms it applies to.
3. Per-platform counts, merged counts and duplicates are recorded
   and reconciled.
4. A platform that fails to load is reported as uncovered; the
   other platforms still produce results and the exit code says
   the result is incomplete.
5. A project with no platform dimension is scanned exactly as
   before, with no extra fields, no extra work and the same exit
   code.

## How to reproduce

```bash
reports/scripts/run.sh /path/to/go
```

The script builds gosec from the repository root, runs it against
the fixtures in `fixtures/`, writes JSON reports to `output/`, and
then asserts every acceptance condition while printing the actual
numbers. It exits non-zero if any check fails.

## Fixtures

### `fixtures/three-platform`

A module with one package holding four files:

| File | Builds on | Intent |
|------|-----------|--------|
| `common.go` | every platform | one finding shared by all targets |
| `linux_only.go` | linux | one finding unique to linux |
| `darwin_only.go` | darwin | one finding unique to darwin |
| `windows_only.go` | windows | one finding unique to windows |

Each file has exactly one `os.Chmod(..., 0777)` (G302). Before
the change, scanning this module on Linux saw two of the four
files; scanning it on Windows saw two different files. The
conclusions could not be reproduced across machines.

### `fixtures/broken-platform`

Same shape, but `windows_only.go` calls an undefined function, so
the windows build fails. This models a repository whose code is
broken on one platform — previously the whole scan failed and the
healthy platforms produced nothing.

## Acceptance results

Actual output: `output/three-platform.json`, `output/broken-platform.json`,
`output/single-platform.json`, `output/inferred.json`.

### 1. Three mutually exclusive implementations are all analyzed

Run:

```bash
gosec -platforms=linux/amd64,darwin/arm64,windows/amd64 \
      reports/fixtures/three-platform/app
```

Result: four findings, one per file. `linux_only.go` is
reported with `"platforms": ["linux/amd64"]`, `darwin_only.go`
with `["darwin/arm64"]`, `windows_only.go` with
`["windows/amd64"]`, and the shared `common.go` is reported once
with all three.

### 2. Reconciliation identity

From `output/three-platform.json`:

```
per_platform_total = 6
merged             = 4
duplicates         = 2
6 = 4 + 2          ✓ (balanced)
```

The sum of per-platform hits (2 + 2 + 2 = 6) equals the recorded
total, and the merged count plus duplicates equals it as well, so
the merged result can be checked against the per-platform work.

### 3. Per-platform failure isolation

Run the same command against `fixtures/broken-platform`:

- exit code `2` (incomplete coverage), not `1`;
- `coverage.complete` is `false` and `coverage.missing` is
  `["windows/amd64"]`;
- `failed` names `windows/amd64` with the compiler error;
- the linux and darwin findings and the shared finding are still
  produced.

### 4. Inference without configuration

Running `gosec reports/fixtures/three-platform/app` with no
platform flags infers `darwin/amd64, linux/amd64, windows/amd64`
from the files' build constraints (the host architecture is used
for the bare GOOS names). `output/inferred.json` records
`"source": "inferred"` and a message naming the platforms, and
the windows and darwin findings appear even though the scan ran
on linux.

### 5. Single-platform project is unchanged

Running the three-platform fixture with only the host platform,
or scanning any project whose constraints declare no platform
dimension, produces:

- no `platforms` block in the report;
- no `platforms` field on any issue;
- the same issue count and content as a plain `gosec ./...`.

`output/single-platform.json` demonstrates the first two points.

### 6. Packages that exist on one platform only

A separate check (not part of the committed fixture to keep it
small) scans a module with a package guarded by
`//go:build windows` together with a package that builds
everywhere:

```
gosec -platforms=linux/amd64,windows/amd64 ./...
```

The windows-only package and its finding appear in the result; on
a linux-only machine it was previously invisible.

## Requirement mapping

| Requirement | Where it is met |
|-------------|-----------------|
| one run covers a target set | `-platforms`, `SelectPlatforms` |
| mutually exclusive implementations all analyzed | per-platform build context in `loadForPlatform` |
| single-platform files and packages appear | per-platform loading, recursive package discovery |
| one merged issue listing its platforms | `mergePlatformResults`, `issue.Platforms` |
| filtering and summarizing by platform | `-platform-filter`, `FilterIssuesByPlatform`, report `stats` |
| infer targets when not configured | `InferPlatforms` from build constraints |
| one platform's load failure is isolated | `processMultiPlatform` `failed`/`coverage` |
| single-platform results unchanged | host-only path keeps legacy behavior |
| per-platform hits, merged, duplicates reconcile | `Reconciliation`, `ValidatePlatformReport` |
| platform dimension does not change judgement | per-issue key includes severity/confidence; `conflicts` records violations |
| merging is lossless | `issue.Platforms` retains every hit |
| one run, no manual merge | `ProcessPlatforms` merges in-process |
| concurrency not amplified | platforms scanned sequentially over the same bounded pool |
| bounded cost, trimming reported | `-platforms-max`, `PlatformReport.Excluded` |
| failed platform is marked, exit code reflects it | `exitIncomplete` (2), `coverage.missing` |
| budget trimming is reported | `Excluded`, warning on stderr |
| no silent fallback when nothing can be inferred | `PlatformSourceHost`, explicit messages |

## Host

```
OS:     Linux 6.18.58.1-microsoft-standard-WSL2 (WSL2)
Go:     go1.26.0 linux/amd64
gosec:  dev (built from this repository)
```
