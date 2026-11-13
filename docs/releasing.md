# Publishing a release

This is the checklist for cutting a version. It is written for whoever is holding
the repository, not for CI.

## The gate

Everything below assumes `main` is green on the `tests` workflow: pyflakes, mypy,
349+ tests, and the 90% coverage floor. If that is not true, stop.

    make check          # exactly what CI enforces
    make smoke          # end-to-end CLI, including Sigma import and STIX export

## 1. Bump the version in three places

    cabid/__init__.py     __version__ = "0.8.0"
    pyproject.toml        version = "0.8.0"
    README.md             "alpha prototype (v0.8.0)"

The publish workflow checks that the release tag matches
`cabid/__init__.py`; a mismatch fails the build before anything is uploaded.

## 2. Update CHANGELOG.md

Move `## [Unreleased]` to `## [0.8.0] — YYYY-MM-DD`. Keep the existing shape:
`Added` / `Changed` / `Fixed`, and say plainly when a change affects a score or a
report's status. A reader comparing two reports must be able to find out why they
differ.

## 3. Merge, then tag

    git checkout main && git pull
    git tag -a v0.8.0 -m "CABID v0.8.0"
    git push origin v0.8.0
    gh release create v0.8.0 --title "CABID v0.8.0" --notes-file /tmp/notes.md

The release notes should repeat the honest status line: alpha prototype,
heuristics not probabilities, no real-host benchmark.

## 4. PyPI trusted publishing — one-time setup

Publishing runs from `.github/workflows/publish.yml` on `release: published`. It
uses OIDC, so **no API token is stored in this repository**. That also means PyPI
has to be told to trust this specific workflow, once, by a project owner.

At <https://pypi.org/manage/account/publishing/> add a *pending publisher*:

| Field | Value |
| --- | --- |
| PyPI project name | `cabid` |
| Owner | `sayan9168` |
| Repository name | `CABID` |
| Workflow name | `publish.yml` |
| Environment name | `pypi` |

The environment name matters: the OIDC subject claim includes it
(`repo:sayan9168/CABID:environment:pypi`), so a release published from a job
without `environment: pypi` will be refused even when the other fields match.

If the upload fails with `invalid-publisher`, the pending publisher is missing or
one of those five values differs. The error output prints the claims it presented,
which is the fastest way to spot a mismatch.

Once the first release has published successfully, the pending publisher becomes a
real publisher and later releases need no further setup.

## 5. Verify

    pip download cabid==0.8.0 --no-deps -d /tmp/check
    python -m venv /tmp/v && /tmp/v/bin/pip install cabid==0.8.0
    /tmp/v/bin/cabid --version
    /tmp/v/bin/python -m cabid --version

Also confirm the wheel still has **zero runtime dependencies** — the whole point of
the project's packaging rule:

    python -c "import importlib.metadata as m; print(m.requires('cabid'))"

## Manual publish (only if trusted publishing is unavailable)

    make build
    twine check --strict dist/*
    twine upload dist/*

This needs an API token in `~/.pypirc`. Prefer the workflow; a token in a local
file is a token that can leak.

## Docker

    make docker
    docker run --rm -v "$PWD/datasets:/data:ro" cabid:dev analyze /data/synthetic/example.jsonl

The image is not published to a registry yet. If that changes, add the tag push to
`publish.yml` rather than doing it by hand, so the image and the wheel always
share a version.
