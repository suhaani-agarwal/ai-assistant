#!/usr/bin/env bash
# Opens a pull request in each named repository that adds the shared CI actions (PR labelling, readiness and stale
# handling; or, with --issues, issue management), in preview mode. Run it once, from a laptop, with your own `gh` login; nothing is stored anywhere.
#
#   scripts/adopt-ci.sh --reviewers @your-org/maintainers your-org/repo-a your-org/repo-b
#   scripts/adopt-ci.sh --reviewers @your-org/maintainers --dry-run your-org/repo-a
#   scripts/adopt-ci.sh --issues your-org/repo-a        # issue management instead: no reviewers needed
#   scripts/adopt-ci.sh --update-pin your-org/repo-a    # repos that already use an action: move only its pins
#
# Existing files are never overwritten. The action is pinned to the commit of this checkout, which must be pushed.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source_repo="kyverno/assistant"
ref=""
reviewers=""
dry_run=false
branch=""
update_pin=false
issues=false

die() { echo "error: $*" >&2; exit 1; }

usage() {
  cat << 'EOF'
usage: adopt-ci.sh --reviewers @org/team [options] owner/repo [owner/repo ...]
       adopt-ci.sh --issues [options] owner/repo [owner/repo ...]
       adopt-ci.sh --update-pin [options] owner/repo [owner/repo ...]

  --reviewers @org/team  existing team of the repo's organisation that the bot mentions when a PR needs a maintainer
                         (required, except with --issues or --update-pin)
  --issues               adopt the shared issue management (labels resolved issues, closes ones waiting on the
                         reporter) instead of the PR automation; needs no reviewers. Opens its own PR, so a repo can
                         take either one first
  --update-pin           for repos that already use pr-management or issue-management: rewrite only the pinned action
                         references in their workflows, wherever they point now; add nothing and leave all config alone
  --dry-run              show which files would change; push nothing, open nothing
  --source owner/repo    where the actions live (default: kyverno/assistant)
  --ref SHA              full commit of the source to pin (default: this checkout's HEAD)
  --branch NAME          branch to open the PR from (default: ci/adopt-shared-actions; ci/adopt-issue-management
                         with --issues; ci/update-pr-management-pin with --update-pin)
EOF
}

repos=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reviewers) reviewers="${2:?--reviewers needs a value}"; shift 2 ;;
    --dry-run) dry_run=true; shift ;;
    --update-pin) update_pin=true; shift ;;
    --issues) issues=true; shift ;;
    --source) source_repo="${2:?--source needs a value}"; shift 2 ;;
    --ref) ref="${2:?--ref needs a value}"; shift 2 ;;
    --branch) branch="${2:?--branch needs a value}"; shift 2 ;;
    -h | --help) usage; exit 0 ;;
    -*) usage >&2; die "unknown option $1" ;;
    *) repos+=("$1"); shift ;;
  esac
done

[[ ${#repos[@]} -gt 0 ]] || { usage >&2; die "name at least one owner/repo"; }
[[ "$issues" == "false" || "$update_pin" == "false" ]] || die "--issues and --update-pin cannot be combined: --update-pin moves the pins of both"
if [[ -z "$branch" ]]; then
  if [[ "$update_pin" == "true" ]]; then
    branch="ci/update-pr-management-pin"
  elif [[ "$issues" == "true" ]]; then
    branch="ci/adopt-issue-management"
  else
    branch="ci/adopt-shared-actions"
  fi
fi
[[ "$source_repo" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || die "--source must look like owner/repo"
if [[ "$update_pin" == "false" && "$issues" == "false" ]]; then
  # Same rule as the action's own config check; a single @user is rejected there.
  [[ "$reviewers" =~ ^@[A-Za-z0-9-]+/[A-Za-z0-9_.-]+$ ]] || die "--reviewers must look like @org/team"
fi
for tool in gh git jq; do command -v "$tool" > /dev/null || die "$tool is required"; done
gh auth status > /dev/null 2>&1 || die "run 'gh auth login' first"

if [[ -z "$ref" ]]; then
  ref=$(git -C "$here" rev-parse HEAD)
fi
[[ "$ref" =~ ^[0-9a-f]{40}$ ]] || die "--ref must be a full 40-character commit SHA"
gh api "repos/${source_repo}/commits/${ref}" --jq .sha > /dev/null 2>&1 \
  || die "commit ${ref} is not in ${source_repo}; push this checkout or pass --ref with a pushed commit"
if [[ "$update_pin" == "false" ]]; then
  shared=pr-management.yml
  [[ "$issues" == "false" ]] || shared=issue-management.yml
  gh api "repos/${source_repo}/contents/.github/workflows/${shared}?ref=${ref}" --jq .path > /dev/null 2>&1 \
    || die "commit ${ref} has no .github/workflows/${shared}; use a commit that includes the shared workflows"
fi

templates="$here/adopt-ci-templates"
workflows=(pr-management check-pr-management pr-labelling sync-labels)
[[ "$issues" == "false" ]] || workflows=(issue-management check-issue-management)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

overlap_section() {
  [[ -n "$overlap" ]] || return 0
  cat << EOS

## Existing automation to retire first

These workflows already touch the same labels or run a labeler or stale bot. Once the previews are switched on, both
would act on the same PRs and could add duplicate or conflicting labels and comments. Keep one owner for each job:

$(printf '%s\n' "$overlap" | sed 's/^/- /')
EOS
}

pr_body() {
  cat << EOF
## What this does

Adds the shared PR automation from [${source_repo}](https://github.com/${source_repo}/tree/${ref}/.github/actions/pr-management),
pinned to commit \`${ref}\`. The four workflow files added here are short callers: they say when to run and what
permissions to grant, and call the shared workflows \`pr-management.yml\` and \`pr-management-validate.yml\` in
${source_repo}, which hold the logic, the trusted checkout and the token of each job.

- **Labels** PRs from the paths they change, and flags merge conflicts.
- **Readiness**: marks a PR \`ready-for-review\` or \`needs-author-action\` from its checks and review threads.
- **Stale handling**: warns, then closes PRs the author has left quiet (14 days inactive, at least 7 days after the warning).

## Nothing changes when this merges

The scheduled and PR-event runs are **previews**: they print what they would do (log lines start with \`[dry-run]\`)
and write nothing. A repository admin turns the automation on afterwards.

**Before the switch**

1. Run **Sync labels** from the Actions tab with dry run off, so the lifecycle labels exist. Readiness and stale
   can fail without them.
2. Read a few preview runs, and optionally run **PR lifecycle** by hand (readiness, then stale) with dry run off to
   see real effects once.
3. Adjust the config (see below) to match the repository.
4. If the organisation restricts which actions may run (Settings, Actions, General), allow \`${source_repo}@*\`,
   \`actions/labeler@*\` and \`eps1lon/actions-label-merge-conflict@*\`.

**The switch**: set the repository variable \`PR_AUTOMATION_LIVE\` to \`true\` (Settings, Secrets and variables, Actions,
Variables), or run \`gh variable set PR_AUTOMATION_LIVE --body true --repo ${repo}\`. Creating a variable needs admin
access. No PR is needed.

**After it**: readiness and path labels act on the next PR event (readiness also hourly), and stale in its daily run.
The first live stale run can mark old quiet PRs stale; they cannot be closed until at least 7 days after the warning.
Setting the variable to \`false\`, or deleting it, returns every scheduled and PR-event run to preview.

## What to check in this PR

- \`.github/pr-management.json\`: reviewers (\`${reviewers}\`), exempt labels, timings.
- \`.github/pr-readiness-checks.yml\`: optional changes to the built-in readiness checks (turn one off, replace it, or add your own). It starts as a commented example.
- \`.github/labels.yml\`: add path rules for your areas. It must define the lifecycle labels \`needs-author-action\`,
  \`ready-for-review\`, \`workflow-approval-required\`, \`stale\` and \`merge-conflicts\`; any missing from an existing file are appended to it by this PR.

- If a branch-protection rule requires a check by name, note that the jobs now appear as \`<job> / <shared job>\`
  (for example \`validate / validate\`).

## Keeping it current

The shared workflows are pinned to a full commit SHA so they never change under you. To update, change the SHA in
the four workflow files (a Dependabot \`github-actions\` entry does this for you), or run
\`scripts/adopt-ci.sh --update-pin ${repo}\` from ${source_repo}, which opens a PR that changes only those lines.

$(overlap_section)

Opened with \`scripts/adopt-ci.sh\`. The config check runs on this PR without a token.
EOF
}

issue_body() {
  cat << EOF
## What this does

Adds the shared issue management from [${source_repo}](https://github.com/${source_repo}/tree/${ref}/.github/actions/issue-management),
pinned to commit \`${ref}\`. The two workflow files added here are short callers: they say when to run and what
permissions to grant, and call the shared workflows \`issue-management.yml\` and \`issue-management-validate.yml\` in
${source_repo}, which hold the logic, the trusted checkout and the token.

- **Possibly resolved**: labels an issue \`possibly-resolved\` and asks for confirmation when a merged PR mentions it
  without closing it, no open PR mentions it, and nobody has commented since. Never closes.
- **Waiting on the reporter**: for an issue with a needs-info label and no reply from its author, warns with
  \`stale-issue\` after 14 days and closes as not planned after 14 more. **This is the only rule that closes.** A reply
  from the reporter resets it.
- **Idle and untriaged**: off until \`triage_label\` is set. Then labels \`stale-issue\` after 180 days without human
  activity and lists the oldest untriaged issues in the run summary. Never closes.

Issues with an exempt label or a milestone are never labelled or closed, and any human comment removes \`stale-issue\`
and \`possibly-resolved\`. \`stale-issue\` is not \`stale\`, so it never mixes with PR stale handling.

## Nothing changes when this merges

The scheduled run is a **preview**: it writes what it would do to the job summary and changes nothing. A repository
admin turns it on afterwards.

**Before the switch**

1. Run **Issue management** from the Actions tab with dry run on, and read the job summary.
2. Edit \`.github/issue-management.json\` for the repository: the labels that mean "waiting on the reporter"
   (\`needs_info_labels\`), the labels that exempt an issue (\`exempt_labels\`), and, if you triage with a label,
   \`triage_label\` and \`priority_prefix\`. No label needs creating by hand.
3. If the organisation restricts which actions may run (Settings, Actions, General), allow \`${source_repo}@*\`.

**The switch**: set the repository variable \`ISSUE_AUTOMATION_LIVE\` to \`true\` (Settings, Secrets and variables,
Actions, Variables), or run \`gh variable set ISSUE_AUTOMATION_LIVE --body true --repo ${repo}\`. Creating a variable
needs admin access. No PR is needed. It is separate from \`PR_AUTOMATION_LIVE\`.

**After it**: the daily run changes at most 30 issues. Setting the variable to \`false\`, or deleting it, returns it to
preview.

## Keeping it current

The shared workflows are pinned to a full commit SHA so they never change under you. To update, change the SHA in the
two workflow files (a Dependabot \`github-actions\` entry does this for you), or run
\`scripts/adopt-ci.sh --update-pin ${repo}\` from ${source_repo}, which opens a PR that changes only those lines.

$(overlap_section)

Opened with \`scripts/adopt-ci.sh --issues\`. The config check runs on this PR without a token.
EOF
}

# --update-pin recognises a pinned reference by its shape alone: a `uses:` value that names pr-management or
# issue-management and ends in @ and a full commit SHA. That covers each action and shared workflow, from any source,
# with no list to keep up to date.
pin_re='[^[:space:]]*(pr|issue)-management[^[:space:]@]*@[0-9a-f]{40}'

md_list() { # lines on stdin become a Markdown list of code spans
  # The backticks are Markdown, not command substitution.
  # shellcheck disable=SC2016
  sed 's/^/- `/; s/$/`/'
}

pins_in() { # the pins found in the files named on stdin, one per line
  while IFS= read -r f; do grep -ohE "uses:[[:space:]]*${pin_re}" "$f"; done | sed -E 's/^uses:[[:space:]]*//' | sort -u
}

pin_body() { # old pins, new pins, changed files (each one per line)
  local files_md
  files_md=$(printf '%s\n' "$3" | md_list)
  cat << EOF
## What this does

Moves the pinned references to the shared CI automation (pr-management, issue-management) to commit \`${ref}\` of ${source_repo}. Only the \`uses:\`
lines in the files below change. The config files and every other line of the workflows stay as they are.

Files:

${files_md}

Moved from:

$(printf '%s\n' "$1" | md_list)

Moved to:

$(printf '%s\n' "$2" | md_list)

## What to check

- Read the code at the new pin (https://github.com/${source_repo}/tree/${ref}) if the source or the commit differs.
- If the organisation restricts which actions may run (Settings, Actions, General), allow \`${source_repo}@*\` first,
  or the workflows fail at start.
- After merging: run **Sync labels** by hand, then read the next hourly readiness run.

To roll back, revert this PR; the old pin keeps working.

Opened with \`scripts/adopt-ci.sh --update-pin\`.
EOF
}

publish() { # title; runs in the clone with the branch committed; reads repo, writable and default_branch from adopt
  local head="$branch"
  if [[ "$writable" == "true" ]]; then
    git push --quiet origin "$branch" || return 1
  else
    local login
    login=$(gh api user --jq .login)
    gh repo fork "$repo" --remote --remote-name fork > /dev/null 2>&1 || true
    # With an existing fork, gh prints "already exists" and adds no remote.
    git remote get-url fork > /dev/null 2>&1 || git remote add fork "https://github.com/${login}/${repo#*/}.git"
    git push --quiet fork "$branch" || return 1
    head="${login}:${branch}"
  fi
  gh pr create --repo "$repo" --base "$default_branch" --head "$head" --title "$1" --body-file "$tmp/body.md"
}

update_pins() { # runs in the clone
  local files old new f
  files=$(grep -lE "uses:[[:space:]]*${pin_re}" .github/workflows/* 2> /dev/null || true)
  if [[ -z "$files" ]]; then
    echo "  does not use pr-management or issue-management yet; run without --update-pin to adopt it"
    return 0
  fi
  old=$(printf '%s\n' "$files" | pins_in)
  # Swap the owner/repo and the SHA; the path inside the repository stays as it is.
  printf '%s\n' "$files" | while IFS= read -r f; do
    sed -E -i.bak "s#(uses:[[:space:]]*)[^/[:space:]]+/[^/[:space:]]+(/[^[:space:]@]*(pr|issue)-management[^[:space:]@]*)@[0-9a-f]{40}#\1${source_repo}\2@${ref}#" "$f" \
      && rm -f "$f.bak"
  done
  if git diff --quiet; then
    echo "  already pinned to ${source_repo} at ${ref}, nothing to do"
    return 0
  fi
  git diff --stat | sed 's/^/  /'
  [[ "$dry_run" == "false" ]] || { echo "  dry run: nothing pushed"; return 0; }
  new=$(printf '%s\n' "$files" | pins_in)
  git add -- .github/workflows
  git commit --quiet -s -m "ci: update the shared automation pin" -m "Points the shared automation at ${source_repo} at ${ref}."
  pin_body "$old" "$new" "$(git diff --name-only HEAD~1)" > "$tmp/body.md"
  publish "ci: update the shared automation pin"
}

add_file() { # source, destination (relative to repo root); never overwrites
  local src="$1" dest="$2"
  if [[ -e "$dest" ]]; then
    echo "  kept existing $dest"
    return
  fi
  mkdir -p "$(dirname "$dest")"
  sed -e "s#uses: kyverno/assistant/#uses: ${source_repo}/#" -e "s#@<full-commit-SHA>#@${ref}#" "$src" > "$dest"
  echo "  add $dest"
  added+=("$dest")
}

adopt() {
  local repo="$1" default_branch writable work
  echo "== $repo"
  [[ "$(gh api "repos/${repo}" --jq .archived)" == "false" ]] || { echo "  archived, skipped"; return 0; }
  if [[ "$update_pin" == "false" && "$issues" == "false" ]]; then
    # The team must exist in the repository's own organisation: a mention of any other name notifies nobody.
    team_org=$(printf '%s' "${reviewers#@}" | cut -d/ -f1 | tr '[:upper:]' '[:lower:]')
    team_slug="${reviewers##*/}"
    [[ "$team_org" == "$(printf '%s' "${repo%%/*}" | tr '[:upper:]' '[:lower:]')" ]] \
      || { echo "  skipped: ${reviewers} is not a team of ${repo%%/*}" >&2; return 1; }
    gh api "orgs/${team_org}/teams/${team_slug}" --jq .slug > /dev/null 2>&1 \
      || { echo "  skipped: team ${reviewers} does not exist or is not visible to you" >&2; return 1; }
  fi
  default_branch=$(gh api "repos/${repo}" --jq .default_branch)
  writable=$(gh api "repos/${repo}" --jq .permissions.push)
  if [[ -n "$(gh pr list --repo "$repo" --head "$branch" --state open --json number --jq '.[].number')" ]]; then
    echo "  a PR from ${branch} is already open, skipped"
    return 0
  fi
  work="$tmp/${repo//\//_}"
  gh repo clone "$repo" "$work" -- --depth 1 --quiet
  (
    cd "$work" || exit 1
    git checkout --quiet -b "$branch" || exit 1
    if [[ "$update_pin" == "true" ]]; then
      update_pins || exit 1
      exit 0
    fi
    added=()
    if [[ "$issues" == "true" ]]; then
      overlap=$(grep -lE 'actions/stale|probot/stale|stale-issue|close-stale|stale-bot' .github/workflows/* 2> /dev/null || true)
      if [[ -n "$overlap" ]]; then
        echo "  warning: existing workflows overlap with this automation; retire one before switching it on:" >&2
        printf '%s\n' "$overlap" | sed 's/^/    /' >&2
      fi
      for name in "${workflows[@]}"; do add_file "$templates/workflows/$name.yaml" ".github/workflows/$name.yaml"; done
      add_file "$templates/issue-management.json" .github/issue-management.json
      [[ ${#added[@]} -gt 0 ]] || { echo "  already adopted, nothing to add"; exit 0; }
      [[ "$dry_run" == "false" ]] || { echo "  dry run: nothing pushed"; exit 0; }
      git add -- "${added[@]}"
      git commit --quiet -s -m "ci: adopt the shared issue management" \
        -m "Pins ${source_repo}/.github/actions/issue-management at ${ref}."
      issue_body > "$tmp/body.md"
      publish "ci: adopt the shared issue management" || exit 1
      exit 0
    fi
    overlap=$(grep -lE 'needs-author-action|ready-for-review|actions/stale|actions/labeler' .github/workflows/* 2> /dev/null || true)
    if [[ -n "$overlap" ]]; then
      echo "  warning: existing workflows overlap with this automation; retire one before switching it on:" >&2
      printf '%s\n' "$overlap" | sed 's/^/    /' >&2
    fi
    for name in "${workflows[@]}"; do add_file "$templates/workflows/$name.yaml" ".github/workflows/$name.yaml"; done
    if [[ -e .github/pr-management.json ]]; then
      echo "  kept existing .github/pr-management.json"
    else
      mkdir -p .github
      jq --arg r "$reviewers" '.fallback_reviewers = $r' "$templates/pr-management.json" > .github/pr-management.json
      echo "  add .github/pr-management.json"
      added+=(.github/pr-management.json)
    fi
    add_file "$templates/pr-readiness-checks.yml" .github/pr-readiness-checks.yml
    add_file "$templates/labels.yml" .github/labels.yml
    # An existing labels.yml keeps everything it has; only the lifecycle labels the action needs are appended to it.
    labels_appended=false
    for label in needs-author-action ready-for-review workflow-approval-required stale merge-conflicts; do
      grep -qE "^[\"']?${label}[\"']?:" .github/labels.yml && continue
      [[ -z "$(tail -c1 .github/labels.yml)" ]] || echo >> .github/labels.yml
      awk -v key="${label}:" '$0 == key { on = 1; print; next } on && /^[ \t]/ { print; next } { on = 0 }' "$templates/labels.yml" >> .github/labels.yml
      echo "  append '${label}' to .github/labels.yml"
      labels_appended=true
    done
    if [[ "$labels_appended" == "true" ]]; then added+=(.github/labels.yml); fi

    [[ ${#added[@]} -gt 0 ]] || { echo "  already adopted, nothing to add"; exit 0; }
    [[ "$dry_run" == "false" ]] || { echo "  dry run: nothing pushed"; exit 0; }

    git add -- "${added[@]}"
    git commit --quiet -s -m "ci: adopt the shared PR automation" \
      -m "Pins ${source_repo}/.github/actions/pr-management at ${ref}."
    pr_body > "$tmp/body.md"
    publish "ci: adopt the shared PR automation" || exit 1
  )
}

failed=0
for repo in "${repos[@]}"; do
  [[ "$repo" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || { echo "skipping '$repo': not owner/repo" >&2; failed=1; continue; }
  adopt "$repo" || { echo "  FAILED: $repo" >&2; failed=1; }
done
exit "$failed"
