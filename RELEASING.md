# Releasing

`tiny-ecdh-python` is published to PyPI by the `Release` workflow
(`.github/workflows/release.yml`), triggered by pushing a `v*` tag. Publishing
uses PyPI Trusted Publishing (OpenID Connect): no API token is stored in the
repository, the CI, or anyone's shell. Every upload carries a PEP 740 build
provenance attestation.

The version is recorded in exactly one place: `tiny_ecdh/_version.py`. It is
exposed as `tiny_ecdh.__version__` and, through the dynamic `version` field in
`pyproject.toml`, as the distribution version. The tag must match it.

Version bumps are done by hand; automating them is out of scope.

## One-time setup (before the first release)

The package name has never been published, so a **pending publisher** must be
registered on both indexes before any upload. Do this from an account that will
own the project.

1. **TestPyPI pending publisher** — https://test.pypi.org/manage/account/publishing/
   - PyPI Project Name: `tiny-ecdh-python`
   - Owner: `danielsousaoliveira`
   - Repository name: `tiny-ECDH-python`
   - Workflow name: `release.yml`
   - Environment name: `testpypi`

2. **PyPI pending publisher** — https://pypi.org/manage/account/publishing/
   - Same values, except Environment name: `pypi`

3. **GitHub environments** — repository Settings -> Environments, create:
   - `testpypi`
   - `pypi` — add required reviewers so a human approves the real-index upload.

   The environment `url:` fields in the workflow are cosmetic; the names must
   match the pending publishers exactly.

No secrets are added to the repository at any point. If you ever see a prompt
to paste a token, stop.

## Cutting a release

1. Make sure `main` is green in CI and every blocking ticket is done.

2. Pick the version. Pre-1.0 and pre-release only for now — the interface is
   not stable. Use a PEP 440 pre-release segment (`0.1.0a1`, `0.1.0a2`,
   `0.1.0b1`, `0.1.0rc1`, then `0.1.0`). Never reuse a version: a name and
   version pair on an index is permanent.

3. On a release branch:
   - Set `__version__` in `tiny_ecdh/_version.py`.
   - In `CHANGELOG.md`, rename the `[0.1.0a1]` heading to the chosen version,
     replace `unreleased` with today's date (`YYYY-MM-DD`), and update the
     compare/tag links at the bottom.
   - Open a PR, get it reviewed and merged.

4. Run the full local pipeline on the merge commit and confirm it is clean:

   ```sh
   UV_CACHE_DIR=/tmp/tiny-ecdh-uv-cache \
   UV_TOOL_DIR=/tmp/tiny-ecdh-uv-tools \
   uvx tox
   ```

5. Tag the merge commit and push the tag:

   ```sh
   git checkout main && git pull
   git tag -a v0.1.0a1 -m "v0.1.0a1"
   git push origin v0.1.0a1
   ```

6. Watch the `Release` workflow:
   - `checks` runs the whole test matrix and the quality environment. Nothing
     builds or publishes if any check fails.
   - `build` verifies the tag matches `_version.py`, builds the sdist and wheel
     with `SOURCE_DATE_EPOCH` pinned to the tagged commit (so the build is
     reproducible from the tag alone), and attaches provenance.
   - `testpypi` uploads to TestPyPI.
   - `testpypi-smoke` installs the uploaded artefact into an empty environment
     on 3.9, 3.10, 3.11 and 3.12 and runs `scripts/smoke_test.py`, which
     performs a full key exchange using only the installed package and asserts
     `tiny_ecdh.__version__` equals the tag.
   - `pypi` waits for the `pypi` environment approval, then uploads to PyPI.
   - `github-release` attaches the artefacts to a GitHub release.

7. **Manual check before approving the `pypi` job:** open
   https://test.pypi.org/project/tiny-ecdh-python/ and confirm the project page
   renders the "Educational only — do not use in production" warning at the top
   of the description. A warning that only exists in the repository does not do
   its job. If it does not render, cancel the run, fix the README, and start a
   new pre-release version — do not approve the PyPI upload.

8. After the `pypi` job succeeds, verify the real page:
   - https://pypi.org/project/tiny-ecdh-python/ shows the same warning.
   - Fresh install works:

     ```sh
     python -m venv /tmp/verify && /tmp/verify/bin/pip install "tiny-ecdh-python==0.1.0a1"
     cd /tmp && /tmp/verify/bin/python "$OLDPWD/scripts/smoke_test.py" 0.1.0a1
     ```

## Reproducing a build locally

```sh
git checkout v0.1.0a1
export SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct v0.1.0a1)"
python -m build
```

The resulting `dist/` artefacts match those built by CI for the same tag.
