# GitHub Actions workflow (not yet at the Actions path)

The CI definition is in `github-actions.yml` in this directory, not under `.github/workflows/`.

The token used to create these repositories can push ordinary files but does not have GitHub's `workflow` scope, so a first push that added `.github/workflows/ci.yml` was rejected. The checks themselves (`bash -n`, ShellCheck, the test suites, ansible-lint) are unchanged and can be run locally as described in the README.

## To enable GitHub Actions

Using an account or token that has the `workflow` scope (the GitHub web UI is sufficient):

```bash
mkdir -p .github/workflows
cp ci/github-actions.yml .github/workflows/ci.yml
git add .github/workflows/ci.yml
git commit -m "Enable GitHub Actions CI from the reviewed workflow file."
git push origin main
```

Do not force-push. After that file is on `main`, Actions will run on push and pull request.
