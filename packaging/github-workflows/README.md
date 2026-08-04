# GitHub Actions workflows

These are shipped here (not under `.github/workflows/`) so the repository can be
pushed with a fine-grained token that lacks the `workflow` scope. To activate:

```bash
mkdir -p .github/workflows
cp packaging/github-workflows/ci.yml packaging/github-workflows/release.yml .github/workflows/
git add .github/workflows && git commit -m "ci: enable workflows" && git push
```

- `ci.yml` — vet + build + test on every push/PR.
- `release.yml` — runs GoReleaser on a `v*` tag to publish binaries + deb/rpm.
