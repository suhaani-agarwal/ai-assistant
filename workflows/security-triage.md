---
description: |
  First-pass triage of unpublished security advisories: tries to reproduce each new or changed report with the
  project's CLI, suggests a CVSS severity and posts one neutral comment on the advisory for the security team. It never
  changes severity or state, and never closes or publishes anything.

# This file is the repository's own configuration: `gh aw add` copies it, and you edit the `with:` block below. The
# behaviour lives in the shared component it imports. Pin that import to a full commit SHA of the assistant repository
# and move the pin on purpose, as with the other shared workflows.
#
# Add it ONLY to a private repository: the run's logs carry unpublished report text. It reaches the target repository's
# advisories through a GitHub App with "Repository security advisories: read & write" (and nothing else) installed on
# the target, whose client ID and private key are this repository's SECURITY_TRIAGE_APP_CLIENT_ID and
# SECURITY_TRIAGE_APP_PRIVATE_KEY secrets.
on:
  schedule: every 6h
  workflow_dispatch:
    inputs:
      ghsa_id:
        description: "Triage only this advisory, even if it has not changed since the last run. Empty for the usual pick."
        required: false
        type: string

# copilot-requests lets the run use the built-in token for Copilot inference, billed to the organization, so no
# personal access token is stored.
permissions:
  contents: read
  copilot-requests: write

# The model the agent runs on. Pinned rather than `auto`: newer models carry always-on safety classifiers that also
# decline benign security work (https://platform.claude.com/docs/en/build-with-claude/refusals-and-fallback). On a
# re-filed advisory, claude-sonnet-5.5 was refused in 3 of 5 runs, claude-opus-5.5 and gpt-6-sol before running
# anything, while claude-sonnet-5 finished 2 of 2.
engine:
  id: copilot
  model: claude-sonnet-5

safe-outputs:
  # Threat detection keeps its default `detection` model instead of inheriting the agent's.
  threat-detection:
    engine:
      id: copilot
      model: detection
  # Preview first: while this is on, each verdict is written to the run summary and nothing is posted on any
  # advisory. Compare a few weeks of previews with the security team's own triage, then delete this line, run
  # `gh aw compile` and commit to go live.
  staged: true

# Each advisory reproduced in the lab takes about ten minutes: a fresh cluster and two installs.
timeout-minutes: 90

# The most AI credits one run may spend. With one advisory per run (limit below) this is a cap per advisory; a
# normal triage stays well under it. A run that reaches it stops: the verdict recorded so far still posts, and an
# advisory with none is marked unfinished and tried again next run. Raise it together with limit. A plain number:
# gh-aw ignores an expression here.
max-ai-credits: 200

imports:
  - uses: kyverno/assistant/workflows/shared/security-triage.md@main
    with:
      # The repository whose advisories are triaged.
      target_repo: "kyverno/kyverno"
      # Mentioned on the first verdict for an advisory and when the result changes. Empty for none.
      team_mentions: ""
      # The most advisories one run triages. One per run keeps max-ai-credits a cap per advisory; at every 6 hours that
      # is up to four a day.
      limit: 1
      # The CLI the agent reproduces with (these are the defaults), and the documents it reads.
      cli_repo: "kyverno/kyverno"
      cli_asset: "kyverno-cli_{tag}_linux_x86_64.tar.gz"
      cli_binary: "kyverno"
      # The threat model, plus the CEL policy docs the agent needs to write v1.20+ policies.
      context_urls:
        - "https://raw.githubusercontent.com/kyverno/website/main/src/content/docs/docs/guides/security.md"
        - "https://raw.githubusercontent.com/kyverno/website/main/src/content/docs/docs/policy-types/cel-libraries.mdx"
        - "https://raw.githubusercontent.com/kyverno/website/main/src/content/docs/docs/guides/migration-to-cel.md"
      # Anything specific to your project that changes how reports are judged.
      extra_rules: >-
        Kyverno runs as an admission controller with cluster-wide read access and, for generate and mutate-existing
        rules, write access granted by the operator. A report that needs the attacker to create or edit policies,
        PolicyExceptions or Kyverno's ConfigMap already assumes cluster-admin-equivalent power unless the report
        shows a namespaced user doing it. Policies with failurePolicy Ignore, excluded namespaces or excluded groups
        behave as configured. Kyverno v1.20 and later reject the legacy kyverno.io policy types (ClusterPolicy,
        Policy). When you test the latest release and it refuses the report's policy for that reason, write the
        equivalent policies.kyverno.io policy (ValidatingPolicy, MutatingPolicy or GeneratingPolicy, or their
        Namespaced variants), run that instead, and say in the evidence which policy you ran on which release. The
        CEL libraries and migration documents in the context directory give the syntax: look a function up there
        before guessing its arguments.
  # A throwaway kind cluster in the run, for reports that need a running cluster. Drop this import for CLI only.
  - uses: kyverno/assistant/workflows/shared/security-triage-lab.md@main
    with:
      helm_repo: "https://kyverno.github.io/kyverno/"
      chart_name: "kyverno"
      release_namespace: "kyverno"
---

# Security advisory triage

The instructions for this workflow come from the imported shared component. Follow them.
