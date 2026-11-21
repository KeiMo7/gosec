# Review report sample

This is the output of

```bash
gosec -review-report review.txt ./app
gosec -review-report review.json -review-format json ./app
```

over the `app` package. The same findings appear in all three views; only
their organization differs. The fixtures are committed next to the package
tests as `report/review/testdata/demo-review.{txt,json}`, and
`report/review/example_test.go` asserts that one finding resolves to the same
key in two different views.

## Text view

```text
gosec review report

Summary: 16 findings in 4 files (56 lines), 0 suppressed, 0 excluded by path rules, 0 below the severity/confidence threshold

== By severity ==
-- MEDIUM (15) --
  app/main.go:4:2  G501  Blocklisted import crypto/md5: weak cryptographic primitive
  app/main.go:11:14  G401  Use of weak cryptographic primitive
  app/main.go:12:9  G204  Subprocess launched with variable
  app/main.go:14:10  G304  Potential file inclusion via variable
  app/main.go:21:7  G401  Use of weak cryptographic primitive
  app/main.go:23:9  G204  Subprocess launched with variable
  app/many.go:3:8  G501  Blocklisted import crypto/md5: weak cryptographic primitive
  app/many.go:6:6  G401  Use of weak cryptographic primitive
  app/many.go:7:6  G401  Use of weak cryptographic primitive
  app/many.go:8:6  G401  Use of weak cryptographic primitive
  app/shared.go:6:2  G302  Expect file permissions to be 0600 or less
  app/shared.go:6:2  G304  Potential file inclusion via variable
  app/util.go:4:2  G501  Blocklisted import crypto/md5: weak cryptographic primitive
  app/util.go:9:6  G401  Use of weak cryptographic primitive
  app/util.go:10:9  G304  Potential file inclusion via variable

-- LOW (1) --
  app/shared.go:6:2  G104  Errors unhandled

== By file ==

app/main.go
  (top level)
    line 4, column 2
      G501   MEDIUM       Blocklisted import crypto/md5: weak cryptographic primitive
  risky
    line 11, column 14
      G401   MEDIUM       Use of weak cryptographic primitive
    line 12, column 9
      G204   MEDIUM       Subprocess launched with variable
    line 14, column 10
      G304   MEDIUM       Potential file inclusion via variable
  another
    line 21, column 7
      G401   MEDIUM       Use of weak cryptographic primitive
    line 23, column 9
      G204   MEDIUM       Subprocess launched with variable

app/many.go
  (top level)
    line 3, column 8
      G501   MEDIUM       Blocklisted import crypto/md5: weak cryptographic primitive
  many
    line 6, column 6
      G401   MEDIUM       Use of weak cryptographic primitive
    line 7, column 6
      G401   MEDIUM       Use of weak cryptographic primitive
    line 8, column 6
      G401   MEDIUM       Use of weak cryptographic primitive

app/shared.go
  shared
    line 6, column 2
      G104   LOW          Errors unhandled
      G302   MEDIUM       Expect file permissions to be 0600 or less
      G304   MEDIUM       Potential file inclusion via variable

app/util.go
  (top level)
    line 4, column 2
      G501   MEDIUM       Blocklisted import crypto/md5: weak cryptographic primitive
  util
    line 9, column 6
      G401   MEDIUM       Use of weak cryptographic primitive
    line 10, column 9
      G304   MEDIUM       Potential file inclusion via variable

== By rule ==
-- G104 (1 findings, LOW) --
  app/shared.go:6:2  Errors unhandled

-- G204 (2 findings, MEDIUM) --
  app/main.go:12:9  Subprocess launched with variable
  app/main.go:23:9  Subprocess launched with variable

-- G302 (1 findings, MEDIUM) --
  app/shared.go:6:2  Expect file permissions to be 0600 or less

-- G304 (3 findings, MEDIUM) --
  app/main.go:14:10  Potential file inclusion via variable
  app/shared.go:6:2  Potential file inclusion via variable
  app/util.go:10:9  Potential file inclusion via variable

-- G401 (6 findings, MEDIUM) --
  app/main.go:11:14  Use of weak cryptographic primitive
  app/main.go:21:7  Use of weak cryptographic primitive
  app/many.go:6:6  Use of weak cryptographic primitive
  app/many.go:7:6  Use of weak cryptographic primitive
  app/many.go:8:6  Use of weak cryptographic primitive
  app/util.go:9:6  Use of weak cryptographic primitive

-- G501 (3 findings, MEDIUM) --
  app/main.go:4:2  Blocklisted import crypto/md5: weak cryptographic primitive
  app/many.go:3:8  Blocklisted import crypto/md5: weak cryptographic primitive
  app/util.go:4:2  Blocklisted import crypto/md5: weak cryptographic primitive
```

## How the views correspond

Take `app/shared.go` line 6. One statement, three rules:

| View | Excerpt |
| --- | --- |
| by file | `app/shared.go` → `shared` → line 6, column 2 → G104 LOW, G302 MEDIUM, G304 MEDIUM |
| by severity | G302 and G304 under `MEDIUM`, G104 under `LOW`, all at `app/shared.go:6:2` |
| by rule | G104, G302, G304 each list `app/shared.go:6:2` |

The JSON file view nests this as `byFile[].functions[].locations[]`, where one
location carries all three findings and their `ruleIds`.

In JSON each of those entries carries a `key`, and the key is identical in
every view:

```json
{
  "key": "G104@app/shared.go:6:2#de64c041",
  "ruleId": "G104",
  "severity": "LOW",
  "confidence": "HIGH",
  "file": "app/shared.go",
  "line": 6,
  "column": 2,
  "function": "shared",
  "what": "Errors unhandled"
}
```

The key is `RULE@path:line:column#hash`, where `path` is relative to the
nearest `go.mod` (or to the scan root when there is none). It does not encode
time, goroutine order, or which other findings were present, so:

- the same problem keeps the same key when the scan covers one package instead
  of the whole module (see `TestKeysAreStableAcrossScanScopes`);
- the same problem keeps the same key across two runs of the same scan, and the
  whole report is byte-identical (see `TestReportIsByteIdenticalAcrossRuns` and
  `TestReviewReportIsDeterministicAndNamesExclusions`).

Also note in `app/many.go`: the same rule firing three times in `many` is reported
three times, each at its own statement (lines 6, 7, 8), never collapsed into a
single entry or truncated to the first hit.

## Excluded directories

When a directory is removed with `-exclude-dir`, the report names it so that
its absence is not read as "scanned, no findings":

```text
gosec review report
Excluded from the scan:
  vendor (1 directory)
    - vendor/lib
```
