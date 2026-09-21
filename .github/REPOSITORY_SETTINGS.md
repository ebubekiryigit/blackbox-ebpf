# Repository settings

Apply these settings after creating the GitHub repository. They are maintained
here because GitHub rules and security settings are not fully represented by the
tracked workflow files.

## Main branch ruleset

Target the `main` branch and enable the ruleset. Configure it to:

- require a pull request before merging
- require one approving review and a Code Owner review
- dismiss stale approvals when new commits are pushed
- require all review conversations to be resolved
- require linear history and block force pushes and branch deletion
- require `portable (ubuntu-latest)`, `portable (macos-latest)`,
  `generated-bytecode`, and `fuzz-smoke` to pass
- leave `kernel` non-required until its runner behavior is proven stable
- give only the maintainer a pull-request-only bypass

Allow squash merging and automatically delete merged branches. Disable direct
merge commits. Keep `.github/CODEOWNERS` assigned to the maintainer before
enabling the Code Owner requirement.

## Actions and dependency security

- use read-only workflow permissions by default
- do not allow GitHub Actions to create or approve pull requests
- allow GitHub-authored actions; review any exception before adding it
- require approval for workflows from all outside collaborators
- enable the dependency graph, Dependabot alerts, and security updates
- enable secret scanning and push protection when available for the repository

Workflow actions are pinned to full commit hashes. Dependabot tracks Go modules,
the build-only license tool, and GitHub Actions.

## Vulnerability reporting

GitHub Private Vulnerability Reporting can be enabled after the repository becomes
public. Enable it before announcing the public preview and confirm that the
**Security → Report a vulnerability** flow works. Until then, keep the repository
private and do not claim that the reporting form is available.
