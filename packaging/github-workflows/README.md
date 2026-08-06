# GitHub Actions workflows

These are the maintained source copies for CI and release automation. The active
release workflow is also committed at `.github/workflows/release.yml`; keep the
two release files synchronized when changing the release process. GitHub rejects
a workflow change when the credential lacks workflow permission:

```
! [remote rejected] main -> main (refusing to allow a Personal Access Token to
  create or update workflow `.github/workflows/ci.yml` without `workflow` scope)
```

The copy in this directory is inert; the file under `.github/workflows/` is what
GitHub Actions runs.

## Activating them

Either grant the token the `workflow` scope (classic PAT) or the
**Workflows: read and write** permission (fine-grained token), then:

```bash
mkdir -p .github/workflows
cp packaging/github-workflows/ci.yml packaging/github-workflows/release.yml .github/workflows/
git add .github/workflows
git commit -m "ci: enable workflows"
git push
```

Or commit them through the GitHub web UI, which is not subject to the same
token restriction.

## What they do

- **`ci.yml`** — gofmt, vet, build and test on every push and pull request.

- **`release.yml`** — everything a `v*` tag should produce, from one commit and
  one test run:

  | Job | Result |
  |---|---|
  | `gate` | gofmt · vet · build · test · container build — nothing publishes unless all pass |
  | `binaries` | linux amd64+arm64 binaries, deb/rpm, checksums, SBOMs, `install.sh` + `.sha256` |
  | `image` | `ghcr.io/paranoideveloper/forgepanel` for amd64+arm64, with provenance, SBOM and keyless cosign signature |
  | `verify` | checks what was actually published: assets present, checksums match, both arches in the manifest, image starts and is healthy, migrations run, data survives recreation, versions match, tag policy holds |

  Tag policy: a stable release publishes `vX.Y.Z`, `X.Y`, `X` and `latest`; a
  prerelease publishes only its exact tag and never moves `latest`.

## One-time repository setup

The first release will also need, in the repository settings:

1. **Actions → General → Workflow permissions** — the release job requests
   `packages: write` and `id-token: write` per-job, so the default read-only
   token is fine, but Actions must be enabled for the repository.
2. **Packages** — the first push creates `ghcr.io/paranoideveloper/forgepanel`
   as a private package. Make it public and link it to this repository under
   *Package settings* if you want unauthenticated `docker pull` to work.

No secrets need to be created: `GITHUB_TOKEN` covers both the release upload and
the GHCR push, and cosign signs keylessly using the workflow's OIDC identity.
