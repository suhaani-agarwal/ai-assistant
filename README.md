# AI Agent for open-source maintenance

Maintaining an open-source project has become a daily grind of pull requests and issues:

- **The queue never stops.** Every day brings more PRs and issues than one maintainer can read, so the work is sorting
  them: good, stale, ready for review, waiting on the author.
- **The small stuff adds up.** Nudging quiet authors, asking for a rebase, closing abandoned PRs, and explaining the same
  things again to every first-time contributor.
- **Quality is dropping.** More PRs arrive unfinished, unreviewed by their own author or unaware of the project's
  conventions, and each one still needs a careful read.
- **Context is hard to hold.** Which PRs and issues are linked, which PR to merge first, which milestone something
  belongs to, and who is already working on what.

An AI agent can take on this work, but the one you already use for coding is the wrong one to point at it. It runs on the
machine you also use for your job, so while it reads an open-source project it can reach your company's code, documents and
credentials, read your tokens, and take actions or make reads you never meant it to. Open-source repositories are public
input anyone can write to, which makes that worse.

Contributors have the opposite problem: they do not know where to start. They cannot tell which issues are worth taking,
which are already claimed, fixed or deliberately left alone, what the project expects of a change, or what to learn next to
grow from a first PR toward reviewer.

This project answers all three. A **maintainer assistant** works the queue for you, a **contributor assistant** points
contributors to the right work with the context to do it well, and both run in an [OpenShell](https://github.com/NVIDIA/OpenShell)
sandbox that cannot see the rest of your computer.

**AI assistants that work with the full context of an open-source project, and run in a sandbox that cannot see anything
else on your computer.**

A **maintainer assistant** works your pull-request queue and issue backlog and explains every call with a link. A
**contributor assistant** gives you the context to work on a project without being blind to its code, its history and how
its repository works, and tells you what to focus on. **Shared CI actions** keep the labels both of them rely on. All of it
is built on [Hermes](https://hermes-agent.nousresearch.com) and runs inside an [OpenShell](https://github.com/NVIDIA/OpenShell)
sandbox. Kyverno is the first project to use it.

> 🔒 **Safe to run on the laptop you also use for work.** The agent lives in its own sandbox: nothing from your computer is
> mounted into it, and your GitHub token never enters it. [How OpenShell protects you](#protected-by-openshell).

> 🚀 **You do not clone this repository.** It ships as a signed container image on GHCR, and one command takes the launcher
> from that image and runs it. **First, [prepare your repository](#prepare-your-repository)**: a few minutes to adopt the
> shared CI labels and add a few files, which is what makes the assistant sharp. Then:
>
> ```bash
> curl -fsSL https://raw.githubusercontent.com/kyverno/assistant/main/install.sh | sh
> ```
>
> You need Docker, a GitHub account, and a GitHub Copilot subscription (or another model key). [Details below.](#get-started)

## Contents

[What this is](#what-this-is) · [Key features](#key-features) · [The two assistants](#the-two-assistants) ·
[The dashboard](#the-dashboard) · [Get started](#get-started) · [The maintainer assistant](#the-maintainer-assistant) ·
[The contributor assistant](#the-contributor-assistant) · [Shared CI actions](#shared-ci-actions) ·
[Prepare your repository](#prepare-your-repository) · [Built on Hermes](#built-on-hermes) ·
[Protected by OpenShell](#protected-by-openshell) · [Capabilities](#capabilities) ·
[What is verified, and the limits](#what-is-verified-and-the-limits) · [Roadmap](#roadmap) · [Documentation](#documentation)

## What this is

Three independent layers. Take one, or all of them:

| Layer | What it is | Needs a model? | Who adopts it |
|---|---|---|---|
| **Shared CI actions** (`.github/actions/`) | GitHub Actions that label PRs from the paths they change, mark each PR `ready-for-review` or `needs-author-action` from its checks and review threads, and warn and then close PRs and issues an author has left quiet | No | A repository, from a workflow file |
| **Maintainer assistant** | An on-demand agent that builds your review queue, orders it, briefs you on any PR, triages issues and Discussions, and does the follow-up paperwork | Yes | One maintainer, on their own machine |
| **Contributor assistant** | An on-demand coach with the context of the whole project: its docs, its code, its history and what its maintainers decided before. It tells you what to work on, how to contribute, and helps you understand the codebase | Yes | One contributor |

The layers share data: the CI actions label things in a fixed way, and the assistants read those labels instead of
recomputing them. A repository that runs the actions gives the maintainer assistant its signals for free.

![Where each piece runs: the OpenShell gateway on your laptop, the sandbox and supervisor containers in Docker, and the listed services outside](public/highlevel_arch.png)

*Where each piece runs. The gateway is a background service on your laptop; the sandbox and its supervisor are two Docker containers.*

## Key features

**For maintainers**
- 📋 **An ordered merge queue with a reason for every position:** stacked branches, generated-file order, "depends on #N"
  references, competing PRs, same-file and same-package overlaps, rebase flags, and the branch gate, all computed, none guessed
- 🔍 **PR briefs**, short by default and deep on request: what it changes, why, review threads, risk, a suggested action
- 🤖 **Dependabot verdicts** (merge now, fix first, your review, wait, close) based on who actually calls the dependency
- 🏷️ **Issue triage grounded in the real code**, with duplicates, competing PRs and how far along each fix is
- 🧹 **Stale and abandoned PR decisions:** close, reassign, or take over the branch, with the reason from the linked issue
- 💬 **GitHub Discussions:** reads the thread and drafts a reply, posted only when you say so
- ✅ **Actions with your own token** (labels, comments, change requests, approvals, branch updates), on your request

**For contributors**
- 🧭 **Project context for you and the AI:** the docs that govern a path, how the code fits together, who imports it, what
  earlier PRs in the area decided and why, and each issue's full story
- 🎯 **What to work on, how to contribute, and how the code works,** ending with you explaining it back
- 🧪 **Evidence-backed changes:** reproduce, change and test in the sandbox, with a ledger of what was really run
- 📈 **Review feedback explained,** and your path from a first PR toward reviewer

**For both**
- 🖥️ **A dashboard** that shows what the agent just told you, linked and grouped ([below](#the-dashboard))
- 🧠 **Long-term memory:** past incidents, decisions, rejected PRs, your working style and your progress
- 💻 **A coding environment in the sandbox:** clone, install the toolchains a repository declares (Go, Node, the Kyverno CLI
  and Chainsaw), build and test, then get a patch, or a push to your own fork if you turn that on
- 🔌 **Your choice of model:** GitHub Copilot by default, or Anthropic, OpenAI or NVIDIA with your own key
- 🏢 **Built to be adopted:** one organisation pack for your file rules and merge gate, and an organisation policy for which
  repositories and token types are allowed
- 🔄 **Upgrades that keep your state:** memory, history, sign-in, model and cloned repositories
- 📡 **A weekday review digest in Slack**, from the sandbox (`assistant --slack`). Slack chat and the other scheduled jobs are in the [host install](docs/host-install.md)

## The two assistants

One image holds both. Each has its own sandbox, its own GitHub token and its own memory, and you can run both.

| | **Maintainer** (`--profile maintainer`) | **Contributor** (`--profile contributor`) |
|---|---|---|
| For | People who review and merge a repository's pull requests | People contributing to a repository (configured for Kyverno today) |
| It does | Builds your PR queue, triages issues and Discussions, drafts reviews and follow-ups, proposes a merge order | Finds issues worth doing, explains the code and what earlier PRs decided, helps prepare PRs, explains review feedback |
| Writes to GitHub | Labels, comments, reviews and branch updates with your token, on your request; drafted text shown first | A comment, and a pull request from your own fork, after you have seen the exact text |
| Skills | `pr-queue`, `issue-triage`, `dependabot-queue`, `pr-actions`, `issue-actions`, `author-followup`, `discussions`, `dashboard-sync`, `repo-context` | `find-work`, `understand-code`, `make-the-change`, `review-loop`, `grow` |
| Token | Fine-grained, scoped to the repository, or your `gh` sign-in | Your own account's fine-grained token (read-only is enough to read), or your `gh` sign-in |
| Dashboard | Yes | No |
| Sandbox | `assistant-maint` | `assistant-contrib` |

If you start the launcher without `--profile`, it picks the one you already have a sandbox for, and otherwise asks.

## The dashboard

The maintainer assistant writes what it just told you onto a browser board, so you read the queue there instead of scrolling
the chat or copying links by hand. It runs inside the sandbox; the launcher forwards a port on your laptop and prints the
address:

```
http://127.0.0.1:9219/maintainer?profile=maintainer
```

Pick **Maintainer** in the sidebar under Plugins. It refreshes every 15 seconds and fills whenever the agent answers a queue,
stale-PR, issue-triage or Discussions request.

| Tab | Shows |
|---|---|
| **Overview** | What is waiting on you, grouped by verdict (rescue, decide, review, close, triage...), the milestone and due date, the gate status, recent actions |
| **PRs / Issues / Discussions** | One row per item with a GitHub link, its state (CI, merge state, size, labels) and the agent's verdict and reason. Switch views, filter, search, sort |
| **Detail panel** | A summary, unresolved threads, a graph of related PRs and issues, and any drafted comment waiting for your confirmation, with a copy button |
| **Activity** | Every action you confirmed (approvals, comments, nudges, closes, deferrals), with a timestamp and a link |

The board is read-only (confirming and acting happen in the chat) and reachable only from your own laptop. Details and the
port setting: [`docs/usage.md`](docs/usage.md#the-dashboard).

![The Maintainer dashboard, filled by the agent for the Kyverno repository](public/dashboard_example.png)

*An example board filled by the agent for a Kyverno maintainer.*

## Get started

### What you need

| | |
|---|---|
| **Docker** | Docker Desktop 4.60 or newer on a Mac (running, with at least 4 GB of memory), or Docker Engine on Linux. About 20 GB of free disk |
| **A GitHub account** | The repository you want to work on must be readable by it |
| **A model** | A **GitHub Copilot** subscription (the default), or an Anthropic, OpenAI or NVIDIA API key. See [why Copilot](#why-copilot) |
| **A platform** | Verified on Apple Silicon Macs, and on Linux amd64 on a CI runner. Linux needs kernel 5.13 or newer (for Landlock). Other combinations are untested |

You do **not** install Hermes, Python, or OpenShell, and you do not clone anything. The launcher installs OpenShell if it
is missing.

### Run it

**Before you run it, [prepare your repository](#prepare-your-repository)** so the assistant has the labels and files it reads.
Then:

```bash
curl -fsSL https://raw.githubusercontent.com/kyverno/assistant/main/install.sh | sh
```

The script pulls the signed image from `ghcr.io/kyverno/assistant`, copies the launcher out of it (so the launcher and the
image always come from the same release), runs it, and removes the copy. To make it a command you can type, add this to
your shell profile:

```bash
alias assistant='curl -fsSL https://raw.githubusercontent.com/kyverno/assistant/main/install.sh | sh -s --'
```

Then `assistant`, `assistant --profile contributor`, `assistant --upgrade` and so on. In the rest of the docs,
`assistant` means this.

### What the installer does, and what you do

| Step | What happens | You |
|---|---|---|
| 1. Docker and OpenShell | Checks Docker, installs OpenShell and its gateway if missing | Nothing, unless Docker is not running |
| 2. Image | Pulls the image the first time (about 1.2 GB compressed) | Wait a few minutes |
| 3. GitHub | Asks which assistant (**maintainer** or **contributor**), then the repository as `owner/repo` (it offers a default only if a policy gives one). If your organisation publishes a policy, it offers to use it. Then asks how to authorize GitHub, checks the token against the repository, and stores it **in OpenShell, not in the sandbox** | Type the repository, then sign in |
| 3a. Your repository (maintainer, first run) | Looks at the repository: is there an organisation pack, and is the PR automation adopted? Offers to set up what is missing (each opens a pull request; it asks first), says how to edit each one and where the reference is, and can wait for you to merge them, then run Sync labels and switch the automation on. `assistant setup owner/repo` does the same later. Skipped with no terminal, no `gh` login or `ASSISTANT_SKIP_SETUP=1` | Tick what you want, or none |
| 4. Sandbox | Creates the sandbox and applies the network policy | Wait a minute or two |
| 3c. Slack digest (maintainer, optional) | Asks "Post a daily review digest to Slack?". If yes: a bot token (it prints a prefilled link to create the Slack app), your member or channel ID, and a time. The token is stored **in OpenShell**. `assistant --slack` does this later; `--no-slack` removes it | Answer, then paste one token |
| 5. Copilot | Reads your GitHub username from the token, then starts the GitHub Copilot sign-in: it shows a **code and a page** | Open <https://github.com/login/device>, enter the code, approve it, then pick a model |

The chat opens after about 30 seconds. Only the first run asks questions: after that, `assistant` takes you straight back
in, and it keeps your memory, chat history, sign-in and model across upgrades.

### The two sign-ins

**1. GitHub.** You are offered two ways, and either one ends up stored in OpenShell:

- **Sign in with GitHub (`gh`)**: a browser sign-in, nothing to create. Note that `gh` always asks for broad scopes, so
  the token can act on every repository you can, private ones included. If your organisation's policy requires a
  fine-grained token, this option is not offered.
- **Paste a fine-grained token** scoped to the **one repository**: the tighter option. The permissions it needs are
  [below](#optional-a-token-instead-of-the-gh-sign-in) (maintainer) and in [`docs/getting-started.md`](docs/getting-started.md#tokens) (contributor).

**2. GitHub Copilot (the model).** The launcher starts the same device-code login Copilot's own tools use: it prints a code,
you approve it at github.com/login/device, and Hermes keeps the resulting token inside the sandbox's Hermes home. It is
the model the assistant thinks with. To use a key you already have instead, start with `assistant --provider anthropic`
(or `openai`, `nvidia`): it asks for the key once and keeps it in OpenShell, like the GitHub token.

#### Why Copilot

The people this is built for already have it. CNCF gives **GitHub Copilot Enterprise to official CNCF project
maintainers** (they request it through the CNCF Service Desk; announced in
[December 2025](https://contribute.cncf.io/blog/2025/12/16/github-copilot-enterprise-for-maintainers/)), and GitHub gives
**Copilot Pro free to maintainers of popular open-source projects**
([eligibility](https://docs.github.com/en/copilot/how-tos/manage-your-account/get-free-access-to-copilot-pro)). So there is
no API key to buy, paste or leak: sign in once and go. Which models you can pick depends on your plan.

All the options, per platform, plus upgrading, removing, tokens and troubleshooting:
[`docs/getting-started.md`](docs/getting-started.md).

## The maintainer assistant

It works your pull-request queue and issue backlog the way a careful co-maintainer would: it finds what is ready, works
out the order, explains every call with a link, and does the paperwork.

| The problem | What it does |
|---|---|
| "Which PRs can I merge today?" | Fetches the whole candidate set, drops what is not ready, and gives an order with a reason per PR |
| Merging one PR forces rebases on others | Flags PRs that touch files another PR changes, so you see the rebase coming |
| PRs that depend on each other | Finds stacked branches, "depends on #N" references and generated-file input/output pairs, and orders them |
| A red branch gate blocks everything | States it as a fact on every PR it affects, and leaves the bypass decision to you |
| Dependabot PRs pile up | A verdict per PR (merge now, fix first, your review, wait, close), from who calls the dependency |
| Issues need triage | Classifies from the real code, finds duplicates and competing PRs, says how far along each fix is |
| Stale and abandoned PRs | Recommends close, reassign, or take over the branch, with the reason from the linked issue |
| GitHub Discussions | Reads the thread and drafts a reply; nothing is posted until you say so |
| "What did we decide last time?" | Remembers past incidents, rejected PRs and your working style between sessions |

Everything it says is linked to the PR, issue, file or run it comes from. When it looked and found nothing, it says "not
found there" instead of guessing.

### How it thinks

**Code computes the facts, the model makes the judgment, and you make the decision.** Anything that can be computed exactly
(a dependency, a file overlap, a gate) is computed by a deterministic tool, so the model does not guess it. The model then
explains and ranks, citing what the tools returned.

| Signal | Where it comes from | What it tells you |
|---|---|---|
| Stacked branches | A PR's base branch is another candidate's head | Merge the base first |
| Generated-file order | One PR changes a generated file's *input*, another its *output* | The input has to land first, or the output goes stale |
| Explicit references | "Depends on #N", "Blocked by #N", "Stacks on #N", "Parent: #N" in the body | Order, including PRs outside the set (it fetches their state) |
| Competing PRs | Two PRs close the same issue | Duplicate effort: flagged for you, not ordered |
| Same-file overlap | Two PRs touch one file | A likely rebase conflict; it can compare the real diff hunks to see if the *lines* collide |
| Same-package overlap | Same directory, different files | Cannot conflict in git, but worth reviewing together |
| Rebase flag | A PR touches files an earlier-ranked PR changes | It will need updating after that one merges |
| Branch gate | An open gate-failure issue for the PR's base branch | Merging is blocked on that branch whatever the files; review is not |
| File class | Your organisation pack: generated, API surface, critical, test-only | How risky the change is after merge |
| Past incidents | Its memory of package pairs that broke the post-merge suite before | A specific, citable risk |

Cycles are detected and handed to you by number. Among PRs with no hard dependency between them it ranks with a fixed
ladder and says which rung decided each position: related PRs stay together; **severity of the closing issue**, judged
from its content (critical: crash, outage, data loss, security; then high, medium, low); release-urgency labels and
milestone proximity; bot approval and unresolved threads; the author's relationship to the project; size as a pure
tiebreak. Anything you said this session overrides the ladder. **Readiness is separate from priority:** a high-severity PR
with changes requested or a failing check is never listed under "approve now"; the blocker is named instead.

An illustrative queue answer (numbers invented):

```
Queue for milestone 1.20: 14 of 31 open PRs

Group 1: no hard dependency between these
  #18102  split admission handlers      closes #17990 (CRITICAL: crash on startup)
          ✓ checks green · bot-approved · 0 open threads
          ⚠ #18110 is stacked on this one: merge #18102 first
  #18077  fix cleanup TTL parsing       closes #17811 (HIGH: regression in 1.19)
          ✓ ready · touches pkg/cleanup, also changed by #18090 → review together
Group 2
  #18110  stacked on #18102             ⏳ waits for #18102
  #18090  rename policy fields          ⚠ rebase flag: shares api/v1/policy_types.go with #18102
Gate: main is red (issue #18121). Every PR above is blocked on merge until it clears.
```

### Talking to it

| Ask | You get |
|---|---|
| "What's my review queue for 1.20?" | Asks for a focus if you gave none, then the grouped, ordered queue |
| "Brief me on #1234" | Short by default; deeper on request: threads, risk, suggested action |
| "Which Dependabot PRs can I merge today?" | A verdict per PR with call sites, release notes and review findings |
| "Triage the 10 oldest issues with no PR" | Class, severity, duplicates, competing PRs and progress, grounded in the code |
| "Which stale PRs should I close?" | Close, reassign or take over, each with the issue state behind it |
| "Label #1234 area/cli and ask the author to fix DCO" | Applies the label you asked for, and shows you the comment before posting it |

What you ask for explicitly (a label, an approval) it does and reports; anything with words in it (a comment, a review, a
nudge, a Discussion reply) it drafts and shows you first. Merging stays yours (there is no merge tool), and so does a gate
bypass: it explains why a PR looks unrelated to the failure and names the label, and you apply it. It orders by what it can
prove (files, branches, references), not by whether one change semantically breaks another, and it says so when asked.

## The contributor assistant

Contributing to a project you do not know means working blind: you cannot see which docs govern the file you are about to
change, how the code fits together, who owns it, what earlier PRs in the area decided and why, or whether an issue was left
alone for a reason. The contributor assistant removes that. It gives the AI, and you, **all the context that is needed**,
then tells you **what to focus on**, **how to contribute here**, and helps you **actually understand the codebase**, so the
change you send is one you can explain and defend.

| Context it brings | Where it comes from |
|---|---|
| **What the repository says about a path** | The `AGENTS.md` chain from the root down to the folder, the instruction files that apply, the sections of `ARCHITECTURE.md`, `REVIEW.md` and `DEVELOPMENT.md` that matter, the area labels, and who owns it (CODEOWNERS) |
| **How the code fits together** | A folder's contents, Go imports and exports, **who imports it** (from a clone in the sandbox), its tests, and who changed it recently |
| **History and precedent** | How the same area was changed before: merged precedents, closed and rejected attempts, open work, and **what the maintainers said and why** |
| **Each issue's full story** | Who claimed it, which PRs address it, whether it looks fixed already, and so whether it is a good choice |
| **Where your PR stands** | Review threads from maintainers, humans and bots, failing checks, and what blocks it |
| **You** | The areas you know, what you struggled with, what review taught you, and your progress along the project's ladder |

| Skill | What it does |
|---|---|
| `find-work` | Matches issues to your areas and shows each one's full history *before* recommending it, and how to join work already in progress. It says plainly when an issue is a poor choice |
| `understand-code` | Explains how a file or folder fits in (governing docs, importers, tests, owners, precedent PRs), then reads the code itself. It finishes by asking you to explain it back |
| `make-the-change` | Branch, reproduce, change, test and prove it in the sandbox, with signed-off commits and an evidence ledger. It checks the change against the project's own review rules and drafts the PR from the template |
| `review-loop` | After the PR is open: explains every review comment and failing check, says which look right and which deserve pushback with evidence, and drafts reviews of other people's PRs for you to post |
| `grow` | The path from first PR to reviewer: what you have done, what the project's ladder asks for, and what to work on next |

**You stay the author.** The AI-assistance line in a PR template and every reply to a reviewer are yours to write; it drafts
nothing for those. It never claims a test passed that it did not run. Before a PR is drafted it asks you to explain the cause
and the fix in your own words, because reviewers on these projects read a lot of AI-written PRs and trust the contributor who
knows why the change is right. It writes to GitHub only a comment and a pull request from your own fork, after you have seen
the exact text, and it has no tool for approving or merging. Pushing is off unless you start it with `--push-to-fork`.

It also runs entirely inside the OpenShell sandbox, with its coding environment, so cloning, building and testing a project
never touches the rest of your machine.

**Status:** it works, and it is configured for Kyverno today: its pack carries Kyverno's contribution ladder, and another
project needs more setup for it than for the maintainer assistant ([`docs/contributor.md`](docs/contributor.md)). Background
updates (new reviews, failing checks) need the messaging gateway, which the sandbox does not run yet.

## Shared CI actions

Deterministic composite GitHub Actions that need **no model, no container and no secret of yours**: they run on GitHub with
the workflow's own token, in **preview** (they print what they would do and change nothing) until a repository admin turns
them on.

| Action | What it does |
|---|---|
| [`pr-management`](.github/actions/pr-management/README.md) | Labels PRs from the paths they change; marks each `ready-for-review` or `needs-author-action` from its checks and review threads (DCO and CI built in); flags `workflow-approval-required` and `merge-conflicts`; warns, then closes, PRs an author has left quiet |
| [`issue-management`](.github/actions/issue-management/README.md) | Labels issues a merged PR may have resolved, warns then closes issues waiting on the reporter, flags idle untriaged issues. Only the reporter rule ever closes anything |
| `ci-health` (in review) | A read-only report on one workflow's recent runs: shared root causes, flaky and persistent jobs, the commits since the last green run |

You reference an action from a short workflow (`uses: kyverno/assistant/.github/actions/pr-management@<full commit SHA>`), so
the actions themselves need no checkout. `scripts/adopt-ci.sh` is a helper that opens the adoption PR in each repository you
name. It runs from a checkout of this repository, or with no clone through the launcher (`assistant setup owner/repo`, which also
offers the organisation pack); you can also copy the files from [`adopt-ci-templates/`](adopt-ci-templates/) by hand. Steps, files and permissions:
[`docs/adopting-actions.md`](docs/adopting-actions.md).

## Prepare your repository

The assistants are only as sharp as what your repository tells them. Preparing it takes one command and two pull requests you
review. None of it is needed to start: without it the assistant still runs, and tells you which signals it is missing. All of
it makes the answers better.

### The quick way: one command

From the first release after v0.2.0; needs Docker, `gh` (signed in) and Python 3:

```bash
curl -fsSL https://raw.githubusercontent.com/kyverno/assistant/main/install.sh | sh -s -- setup owner/repo
```

With the `assistant` alias from [Run it](#run-it) it is `assistant setup owner/repo`. The first run of the maintainer
assistant offers the same thing. It:

1. **Looks** at the repository and says what is missing: an organisation pack, the PR automation, the labels, whether the automation is switched on.
2. **Offers each as a checkbox.** Nothing is done without your yes, and each one opens a **pull request** in your repository (from your fork if you cannot push). It never overwrites a file.
3. **Tells you how to make the pull request useful**: how to edit it, what to check, where the reference is.
4. **Can wait** until you merge, then run the Sync labels workflow, check the labels exist, and (if you tick it) switch the automation on.

It is safe to run again: it reports what is done and offers only what is left. `assistant-init` alone (the pack only) runs
with no Docker: `curl -fsSL https://raw.githubusercontent.com/kyverno/assistant/main/container/assistant-init | python3 - owner/repo`.
The sections below say what each part is, so you can review it, change it, or do it by hand.

| You get | Lives in | What it gives the assistant |
|---|---|---|
| **PR automation** (CI) | 4 workflows and 3 config files in `.github/` | The labels it reads to build a queue: who is waiting on a maintainer, who on the author, what is stale |
| **Organisation pack** | `.github/assistant-org.yaml` (and `.github/assistant-org-facts.md`) | What is generated, public API, critical and test-only here, which labels mean "ready", and what CI and releases do |
| **Your own knowledge files** | `CODEOWNERS`, `AGENTS.md`, `labels.yml` | Who owns a path, how the code works, what each label means |

### 1. The PR automation (CI)

Deterministic GitHub Actions that need **no model, no container and no secret of yours**. They run on GitHub with the
workflow's own token, and **preview** (print what they would do, change nothing) until an admin switches them on.

**What it does**
- **Path labels**: labels each PR from the files it changes (rules you write in `.github/labels.yml`), and flags merge conflicts.
- **Readiness**: marks a PR `ready-for-review` or `needs-author-action` from its checks and review threads (DCO and CI are built in).
- **Stale handling**: warns, then closes, PRs the author has left quiet (14 days, with a warning at 7). It never merges anything.
- **Config check**: validates the config on every PR, with no token.

**What the adoption pull request adds**

| File | Purpose |
|---|---|
| `.github/workflows/pr-management.yaml` | readiness (hourly and on PR events) and stale (daily) |
| `.github/workflows/pr-labelling.yaml` | path labels and the merge-conflict label |
| `.github/workflows/sync-labels.yaml` | creates the labels, run by hand once |
| `.github/workflows/check-pr-management.yaml` | validates the config on every PR |
| `.github/pr-management.json` | reviewer team, exempt labels, timings |
| `.github/pr-readiness-checks.yml` | which failing checks block a PR, and which are not the author's to fix |
| `.github/labels.yml` | the label catalogue and path rules |

The workflows are short callers pinned by full commit SHA to a shared workflow in this repository, so the logic never changes
under you. If the repository already has a labeler or stale bot, the pull request lists it: keep one owner for each job.

**What you can customise**

| In | You can change |
|---|---|
| `.github/pr-management.json` | `fallback_reviewers` (the `@org/team` it mentions), `exempt_labels` (never stale, for example `no-stale`, `hold`), `close_days`, `warning_days`, `backlog_days`, `milestone_prefix`, `labels_file` |
| `.github/labels.yml` | path rules for your areas (`area/...`), colours, descriptions, your own labels. The five lifecycle labels below must stay |
| `.github/pr-readiness-checks.yml` | turn a built-in check off (`dco`, `ci`, `infra_checks`, `conflicts`, `threads`, `unanswered`), replace one, or add your own |
| The workflow files | schedules, and the pin (`scripts/adopt-ci.sh --update-pin` moves it) |

**Turning it on.** After you merge: run **Sync labels** (the launcher does this for you, with dry run off), read a few
preview runs, then set the repository variable `PR_AUTOMATION_LIVE=true` (`gh variable set PR_AUTOMATION_LIVE --body true --repo owner/repo`; needs admin).
The first live stale run can mark old quiet PRs stale; they cannot close until at least 7 days after the warning. Set it to
`false` to go back to preview. An organisation that restricts which actions may run must allow `kyverno/assistant@*`,
`actions/labeler@*` and `eps1lon/actions-label-merge-conflict@*`. Full steps, files and permissions:
[`docs/adopting-actions.md`](docs/adopting-actions.md). Without the launcher: `scripts/adopt-ci.sh` from a checkout, or copy
[`adopt-ci-templates/`](adopt-ci-templates/) by hand.

### Labels: what is added, and how they help

Five **lifecycle labels** are required. The adoption pull request adds them to `.github/labels.yml`, and Sync labels creates
them in GitHub. They never delete a label you already have.

| Label | Set when | How it helps the assistant |
|---|---|---|
| `ready-for-review` | Checks pass and threads are resolved: ready for a maintainer | The review queue starts here: "what should I review next" is the PRs that carry it |
| `needs-author-action` | The PR is waiting on its author (a failing check, an unresolved thread, an unanswered review) | Not in the review queue, which is the PRs marked ready; it is where the stale-PR follow-up starts |
| `workflow-approval-required` | CI workflows need a maintainer to approve a run | CI has not run yet, so the PR counts as waiting, not as clean |
| `stale` | No author activity; will be closed if it stays quiet | The set the assistant helps you decide on: close, reassign, or find help |
| `merge-conflicts` | The PR has merge conflicts | Waiting on the author |

Beyond these, your **path labels** (`area/docs`, `area/api`, ...) come from the rules in `.github/labels.yml`. They group work by
area, and the assistant reads each label's description, not just its name. Your own labels (`no-stale`, `hold`, ...) are yours:
list the ones that mean "ready" or "waiting on the author" in the pack (`readiness`), and the assistant will use them too.
Without these labels the assistant still works, but has no readiness signal to go on and says so.

### 2. The organisation pack

One small file holds everything specific to your organisation, never code. Publish it as `.github/assistant-org.yaml` in the
repository itself, or once for all your repositories as `assistant-org.yaml` at the root of `<owner>/.github`. The repository's
file replaces the shared one (nothing is merged). The assistant reads it from the default branch, so a pull request cannot
change its own rules. A running assistant checks GitHub for changes at most every ten minutes, and keeps the last good copy if
GitHub cannot be reached. A file it cannot read is an error, never a silent "no pack".

**Write it with `init`.** `assistant setup` (or `assistant init`) reads the repository with your own `gh` login and proposes what is
generated, API surface and test-only, the guides it finds, CODEOWNERS, label prefixes, review bots and the ready labels. It asks
you to confirm the file classes and to pick the critical code, writes `assistant-org-facts.md` with a draft of how CI runs, and opens
a pull request whose description says what to check. `--dry-run` only prints.

**What you can put in it** (the pull request ends with a comment listing the ones `init` could not know):

| Key | What it tells the assistant |
|---|---|
| `maintainer.file_classes` | Globs for `generated`, `api_surface`, `critical` and `test_only` (and `generated_exceptions`). Highest tier wins. Drives risk and ordering |
| `maintainer.branch_gates` | A check that blocks every merge (a shared end-to-end suite): its status, the issue label that reports it red, a bypass label |
| `maintainer.generated_inputs` | What feeds the generated files, so a PR touching an input merges before one touching the output |
| `maintainer.dependency_bots` | Dependency bumps that need regenerated output in the same PR |
| `maintainer.approval_bots`, `review_bots` | Bots whose approval counts as one signal, and bots whose comments are labelled as a bot's |
| `maintainer.milestones` | How milestones are named, and the labels that mark urgency toward one |
| `readiness` | `ready_labels`, `attention_labels`, `infra_checks` (failures that are not the author's to fix), `checks_file` |
| `agent_docs`, `instructions_dir`, `codeowners`, `labels` | Where your guides, owners file and label catalogue are |
| `assistant-org-facts.md` | Prose, in your words: how CI and releases work, flaky checks, review norms |
| `ladder`, `entry_labels`, ... | Only the contributor assistant reads these |

**Making a good one**
1. **Start from `init`**, then read every glob. A glob that matches the wrong files is worse than none.
2. **Keep `critical` short.** Name the code that costs the most when it is wrong (a schema migration, the core engine, the release workflow). If everything is critical, nothing stands out.
3. **List `api_surface`**: what users call (commands, public tools, API folders). `init` finds it only where a folder says so.
4. **Say what a green PR cannot show** in the facts: a suite that runs only after merge, a release made by a tag, no CI on PRs at all. The assistant repeats what you write, so write only what is true.
5. **Add `infra_checks` and `branch_gates`** if a check often fails for reasons that are not the author's, or one check blocks everyone.
6. **Check it.** Ask the assistant for `repo_pack`: it returns the rules exactly as loaded, or the error that names the key. Then ask for a queue and read the file classification in the answer.
7. **Keep it alive.** Add to the facts' "Where the assistant keeps getting it wrong" whenever it does.

A mistake in the pack is an error that names the key. The full reference, every key with an example, is in
[`docs/organisation-pack.md`](docs/organisation-pack.md). Kyverno's own pack, with real gates and generated inputs, is in
[`container/org/kyverno/`](container/org/kyverno/) as a worked example. To bake a pack into an image you build, see the same page.

### 3. Keep your own knowledge files accurate

It grounds its answers in what your repository says about itself, so the better those files are, the less it guesses:

| File | What the assistant uses it for |
|---|---|
| `CODEOWNERS` | Who owns a changed path; who to hand a stale PR to. Read live, last match wins, as GitHub does |
| `AGENTS.md` (root and per package), `ARCHITECTURE.md` | Grounding an issue or a PR in the real code before classifying it. It finds them with code search when it needs them |
| `.github/labels.yml` | What each label means (it reads the label *descriptions*, not just the names) |
| Your milestones | Release proximity in the ranking |

If a package has no doc, it says its knowledge there is only what the code, owners and history show.

### Optional: a token instead of the `gh` sign-in

Most people use the `gh` sign-in the launcher offers, and have nothing to create. If you want something tighter, or your
organisation's policy requires it, paste a fine-grained token for the **one repository** instead: Contents, Checks and the
alerts **Read**, Pull requests and Issues **Read and write**, and no Contents write or Administration, so GitHub itself refuses
to merge. Step by step: [`docs/setup.md`](docs/setup.md#1-create-a-github-token).

### For organisations: publish an assistant policy

An organisation decides which repositories its people may point the assistant at, and which kind of token they may use, by
publishing `assistant-policy.yaml` at the root of its `.github` repository (an [example](container/assistant-policy.yaml) is
in this repository). When someone enters `acme/api`, the launcher looks for `acme/.github/assistant-policy.yaml` and asks
`Use it?`: answer `n` to go without, or type another location (an https URL or a file). The answer is remembered, and they are
asked again only if the organisation changes the file. Set `ASSISTANT_POLICY` to a file or https URL to skip the questions, or
bake the file into your own image.

| Key | Meaning |
|---|---|
| `repos` | The `owner/repo` patterns (`acme/*`, `acme/api`) the assistant may be started on. Anything else is refused. An owner is never a wildcard |
| `default_repo` | Offered when the launcher asks which repository to work on |
| `fork_repos` | Which fork repositories `--push-to-fork` allows |
| `token` | `fine-grained` refuses a token that can act beyond selected repositories (the `gh` sign-in, a classic token) and does not offer the `gh` sign-in. `any` accepts either |

A policy that cannot be read or is malformed stops the launcher: it never falls back to no limits. The check runs on the
person's machine, so it stops mistakes, not someone who edits their own copy; what the agent can do once it is running is
limited by OpenShell's policies, not by this file. The published image ships Kyverno's policy as the fallback (default
repository, fork names, no limit on repositories).


## Built on Hermes

[Hermes](https://hermes-agent.nousresearch.com) (from Nous Research) is the open-source agent runtime. This project is two
**Hermes profile distributions**, `maintainer` and `contributor`. A profile is a self-contained agent:

| Piece | What it is here |
|---|---|
| `SOUL.md` | The principles: what the agent may do, what it must never do, how it reasons |
| **Skills** | Step-by-step procedures: `pr-queue`, `issue-triage`, `dependabot-queue`, `pr-actions`, `discussions`, `find-work`, `make-the-change`, ... |
| **Plugins** | The deterministic tools, in plain Python: `repo-intel` (fetch, sequencing, the pack) and the dashboard for the maintainer; the contributor's knowledge, history and journey tools |
| **Hooks** | Safety checks that run before a tool does: block merge-like tools, guard `git push`, keep the terminal inside the sandbox |
| **Memory** | A long-term memory plugin, so the assistant recalls incidents, decisions and preferences between sessions |
| **Config** | Which tools each profile may see; for example the contributor's GitHub tool list has no review or merge tool |

Plugins hold the facts, skills hold the method, the model holds the judgment. See [`docs/how-it-works.md`](docs/how-it-works.md)
and [`docs/architecture.md`](docs/architecture.md).

## Protected by OpenShell

The agent runs in an [OpenShell](https://github.com/NVIDIA/OpenShell) sandbox, and OpenShell enforces its limits **from
outside it, where the agent cannot edit them.** That is what lets you run it next to private work, and what makes a tricked
agent harmless: it has nothing to steal and nowhere to send it.

- **It cannot see your computer.** Nothing is mounted into the sandbox: not your files, your other projects, your employer's
  code, your SSH keys or your browser sessions.
- **Your GitHub token never enters it.** The sandbox holds a placeholder; OpenShell swaps in the real token on the way out, only
  to GitHub, only from the listed programs.
- **The network is deny-by-default.** It reaches only an allowlist of GitHub, model and toolchain hosts, limited by path,
  method and program. Your office network is not on it.
- **GitHub is read-only at the proxy.** Merges and GraphQL mutations are refused, and every GitHub tool call is checked by name.
- **The code and safety hooks are read-only** (Landlock), so the agent cannot rewrite its own rules.
- **You see everything it does:** `openshell logs assistant-maint` lists every request, allowed or denied. A blocked host can only
  be opened by a rule you approve on your own computer.
- **Organisations can limit which repositories and token types** the launcher accepts ([above](#for-organisations-publish-an-assistant-policy)).

Honest limit: the sandbox limits what the agent can reach, not whether what it *says* is right, so check the links it cites.
The full list of policies, what happens when the agent is tricked, and the limits:
[`docs/sandbox-security.md`](docs/sandbox-security.md). What was tested: [`docs/container.md`](docs/container.md).

## Capabilities

| | Maintainer | Contributor | CI actions |
|---|---|---|---|
| Runs in the OpenShell sandbox, with no view of your computer | ✅ | ✅ | runs on GitHub |
| Ordered merge queue with reasons, rebase flags, overlaps, gate status | ✅ | | |
| PR briefs, with review threads and risk | ✅ | ✅ (your own PR's state) | |
| Dependabot verdicts with call-site analysis | ✅ | | |
| Issue triage grounded in code; duplicates, competing PRs | ✅ | ✅ (issue history and claims) | ✅ (possibly-resolved, waiting-on-reporter) |
| Finding work worth doing, matched to your areas | | ✅ | |
| Project context: docs, importers, tests, owners, precedent PRs and why | | ✅ | |
| Stale and author-blocked PR decisions | ✅ | | ✅ (warn, then close) |
| Readiness and path labels | reads them | reads them | ✅ |
| Labels, comments, change requests, approvals, branch updates | ✅ on your request | comments and a PR from your fork, text shown first | |
| Discussions: read and draft | ✅ | | |
| Review feedback explained; reviews of others' PRs drafted | | ✅ | |
| Journey and ladder progress | | ✅ | |
| Long-term memory | ✅ | ✅ | |
| Dashboard | ✅ | | |
| Coding in the sandbox: clone, toolchains, reproduce, change, test | ✅ | ✅ | |
| Organisation policy on repositories and token types | ✅ | ✅ | |
| Merging | stays yours (no merge tool) | stays yours (no merge tool) | stays yours |

Everything each assistant can do, in detail: [`docs/capabilities.md`](docs/capabilities.md). The review digest works in the sandbox
(`--slack`); Slack chat and the other scheduled jobs work in the [host install](docs/host-install.md) only.

## What is verified, and the limits

**Verified in a real sandbox** (on the image as built): GitHub MCP with a real token (merge tools absent; a merge refused by
the proxy with `policy_denied`); REST and GraphQL mutations refused; the safety hooks; the memory plugin with the network off;
the dashboard; GitHub Copilot sign-in and a model reply; state kept across `--upgrade`. The deterministic maintainer tools were
also run against several repositories that are not Kyverno's, with only a pack.

**Not verified yet:** a full conversation on a non-Kyverno repository; a real reply from Anthropic, OpenAI or NVIDIA keys (the
request reaches them with the key swapped in); a real Slack post and a full model-driven digest (the schedule, the gateway and the delivery path were checked with a placeholder token); the contributor assistant on a project
other than Kyverno.

**Limits to know about:**

- **Structure, not semantics.** The maintainer assistant orders by files, branches and references. Two PRs on different files
  that depend on each other in code are not caught.
- **Review state is partial today.** It reads unresolved threads, bot approvals and checks, not human approvals or requested
  reviewers as structured data. Approval-aware ordering is on the roadmap.
- **One repository at a time**, and replies take on the order of half a minute.
- **Your repository's conventions matter.** Without the shared CI labels or a pack it still runs, and tells you what it is missing.

## Roadmap

The current phase is **data classification and visibility for maintainers**: knowing what is in the queue, how it relates, and
what to do first. What is built is above. What is planned, in order, is not built yet:

| Next | Why |
|---|---|
| Approval-aware context: review decision, who approved, requested reviewers, head commit, computed owners | Answer "which merge will wipe approvals on the others?" from data |
| A fetch layer that retries and updates incrementally, plus a local git mirror for history, owners and conflicts | Faster, cheaper answers; code relations in milliseconds |
| A merge-order planner that minimises rebases and re-approvals, tests merges, and orders by risk | Fewer rebases when a batch lands |
| A snapshot the CI publishes, so every answer starts warm | The same answers in chat, in CI and on the dashboard |
| The contributor assistant for any project (without a required ladder) | Today it is configured for Kyverno |
| More shared CI actions: security triage, vulnerability scanning | Same preview-first design |

## Documentation

| For | Read |
|---|---|
| Installing, per platform; sign-ins, tokens, models, organisation policy, upgrading, removing, troubleshooting | [`docs/getting-started.md`](docs/getting-started.md) |
| Daily use, data, the dashboard, coding in the sandbox | [`docs/usage.md`](docs/usage.md), [`docs/setup.md`](docs/setup.md) |
| Adopting the CI actions | [`docs/adopting-actions.md`](docs/adopting-actions.md), [`.github/actions/`](.github/actions/README.md) |
| Writing your organisation pack | [`docs/organisation-pack.md`](docs/organisation-pack.md) |
| Security: the policies, what was tested, and the design | [`docs/sandbox-security.md`](docs/sandbox-security.md), [`docs/container.md`](docs/container.md), [`docs/openshell-architecture.md`](docs/openshell-architecture.md), [`SECURITY.md`](SECURITY.md) |
| How it works and why | [`docs/how-it-works.md`](docs/how-it-works.md), [`docs/architecture.md`](docs/architecture.md) |
| Everything each assistant can do | [`docs/capabilities.md`](docs/capabilities.md) |
| The contributor assistant | [`docs/contributor.md`](docs/contributor.md) |
| Running on your host instead of a sandbox | [`docs/host-install.md`](docs/host-install.md) |
| Working on this repository | [`docs/development.md`](docs/development.md) |

Licensed under Apache-2.0.