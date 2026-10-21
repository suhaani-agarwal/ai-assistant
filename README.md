# kyverno-assistant

An on-demand review assistant for a Kyverno maintainer. It orders your PR queue, briefs you on
individual PRs, triages issues and Discussions, and acts on GitHub with your own credentials. It
**cannot merge**.

It runs inside a locked-down [OpenShell](https://github.com/NVIDIA/OpenShell) sandbox on your own
laptop: one Docker container that holds [Hermes](https://hermes-agent.nousresearch.com), this
distribution's profile and its memory. Your GitHub token is kept outside the sandbox, and the sandbox can
only reach the few hosts it needs. You start it with one command and talk to it in the terminal. There is no
server to run and no webhook receiver.

> **Status:** works today, on Apple Silicon Macs. Not yet validated across multiple maintainers' real
> workflows (see the validation plan in [`docs/deployment.md`](docs/deployment.md)). Slack and scheduled jobs are
> not available in the sandbox yet; they work in the [host install](docs/host-install.md).

## Contents

- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Setup, step by step](#setup-step-by-step)
- [Everyday use](#everyday-use)
- [Where your data lives](#where-your-data-lives)
- [How it stays safe](#how-it-stays-safe)
- [Why it is built this way](#why-it-is-built-this-way)
- [Troubleshooting](#troubleshooting)
- [Removing everything](#removing-everything)
- [What it does](#what-it-does)
- [The dashboard](#the-dashboard)
- [Slack and scheduled jobs](#slack-and-scheduled-jobs)
- [Repository layout](#repository-layout)
- [Further reading](#further-reading)

## How it works

```
 your laptop
 ┌────────────────────────────────────────────────────────────────────────────┐
 │                                                                            │
 │   you ──► container/kyverno ──► OpenShell gateway                          │
 │           (the launcher)         • keeps your GitHub token (and any model  │
 │                                    API key) so the sandbox never holds it  │
 │                                  • a proxy that allows only listed hosts   │
 │                                    and adds the token on the way out       │
 │                                         │                                  │
 │              ┌──────────────────────────▼───────────────────────────────┐  │
 │              │  the sandbox: one Docker container, built from the image │  │
 │              │   Hermes + this profile + memory + the agent's terminal  │  │
 │              │   holds only a placeholder where your token would be     │  │
 │              └───────────────────────────┬──────────────────────────────┘  │
 └──────────────────────────────────────────┼─────────────────────────────────┘
                                            ▼
                      GitHub (reads; the GitHub MCP server)    Copilot or another model
```

Three pieces, and each one has a job:

- **The image** is a ready-made copy of everything the agent needs: Hermes at a pinned version, this profile,
  its memory plugin and the models it uses. Nothing is installed on your laptop and nothing is downloaded when
  you chat. It is built once ([why](#why-it-is-built-this-way)).
- **The sandbox** is that image running inside OpenShell. The agent works here: it reads GitHub, thinks, remembers,
  and can run commands, but only inside this container, which has no access to your files.
- **The OpenShell gateway** sits between the sandbox and the internet. It holds your GitHub token and, when the
  sandbox calls GitHub, it adds the real token on the way out. If the agent were tricked into printing its
  credentials, it would print a meaningless placeholder. The gateway also refuses everything not on an allowlist,
  including merging.

The launcher, `container/kyverno`, ties them together. Each run it checks Docker, installs OpenShell if needed,
stores your token, creates or starts the sandbox, and opens the chat.

## Quick start

```bash
git clone https://github.com/kyverno/ai-assistant.git
cd ai-assistant
container/kyverno --build      # first time: builds the image (15 to 30 minutes), then starts it
```

It asks for your GitHub token once (hidden), then shows a GitHub page and a code to approve for the
model sign-in. After that, `container/kyverno` alone gets you back in. Everything it asks is explained in
[Setup, step by step](#setup-step-by-step).

## Setup, step by step

### 0. What you need

| Need | Details |
|---|---|
| **A Mac with Apple Silicon**, or Linux | Tested on Apple Silicon only. See [what runs on which machine](#what-runs-on-which-machine). |
| **[Docker Desktop](https://docs.docker.com/get-docker/) 4.60 or newer** | Must be running. Give Docker at least 4 GB of memory (Docker Desktop → Settings → Resources); an 8 GB Mac is enough. |
| **About 20 GB of free disk** | The image is about 4.2 GB. |
| **A GitHub token** | [Step 1](#1-create-a-github-token). |
| **A model** | A GitHub Copilot account (the free plan works with a few models), or an Anthropic, OpenAI or NVIDIA API key. See [step 4](#4-pick-a-model-that-works). |

You do not install Hermes, Python or OpenShell yourself. If OpenShell is missing, the launcher installs it using
OpenShell's own installer.

### What runs on which machine

The image is built for both chip families (Apple Silicon / arm64, and Intel / AMD, called amd64) and passes its
build-time checks on both. What decides whether the whole thing runs is Docker, OpenShell and the launcher around it.

| Your machine | Status |
|---|---|
| **Mac with Apple Silicon** | Tested: this is where everything was developed and checked, including real chats |
| **Linux, x86_64** | Checked end to end on a GitHub Linux runner (Ubuntu 24.04, kernel 6.17, Docker Engine 28): OpenShell installed, the sandbox started, the token stayed a placeholder, merges were refused by the proxy, the hooks were read-only and the dashboard answered. Not tried on a real Linux laptop. The kernel needs Landlock (Linux 5.13 or newer) |
| **Linux, arm64** | The image is built for it; the launcher has not been tried there |
| **Intel Mac** | Not supported: OpenShell supports macOS on Apple Silicon only |
| **Windows** | OpenShell supports it through WSL2 (experimental); run the launcher inside WSL2. Untested |

The launcher checks your machine first and says so plainly if it is one it cannot support.

### 1. Create a GitHub token

Create a fine-grained personal access token scoped to the repo you will point the assistant at
(for example `kyverno/kyverno`):

| Permission | Access |
|---|---|
| Contents | Read |
| Pull requests | Read & Write |
| Issues | Read & Write |
| Checks | Read |
| Code scanning alerts | Read |
| Dependabot alerts | Read |
| Secret scanning alerts | Read |
| Organization members | Read |

Optional, for the extra tools: Organization projects (Read & Write) for project boards,
Administration (Read) for repository rulesets, Organization custom properties (Read). Tools whose
permission is missing return an error and the rest keep working.

**Do not grant Contents Write, merge, or admin scopes.** Without Contents Write, GitHub itself will not let this
token merge a pull request, which is one of the [layers that stop the assistant merging](#how-it-stays-safe).
See [`docs/architecture.md`](docs/architecture.md) for the reasoning. Keep the token handy; you paste it in step 3.

### 2. Get the image

Pick one:

| Option | Command | Time | Notes |
|---|---|---|---|
| **Build it yourself** | `container/kyverno --build` | 15 to 30 minutes, once | Works today on any supported machine. Downloads about 5 GB while building. |
| **Download the published image** | `container/kyverno` | A few minutes | The default once a release is published (see [why](#why-it-is-built-this-way)). It pulls `ghcr.io/kyverno/ai-assistant:latest`. Until the first release is published, use `--build`. |

### 3. Start it

```bash
container/kyverno --build        # or just: container/kyverno
```

It prints five numbered steps. This is what each one does and what you answer:

| Step | What happens | You do |
|---|---|---|
| **1. Docker and OpenShell** | Checks Docker is running; installs OpenShell if missing | Nothing, unless Docker is not running |
| **2. Image** | Builds or pulls the image | Wait |
| **3. GitHub token** | Asks which repo to manage, then your token (hidden). It checks the token against that repo before keeping it, and stores it in OpenShell | Type the repo (`owner/repo`) and paste the token |
| **4. Sandbox** | Creates the sandbox and applies its network policy (a minute or two the first time) | Wait |
| **5. Assistant** | Asks your GitHub username. Then GitHub Copilot sign-in: it prints a page and a code | Open https://github.com/login/device in your browser, enter the code, approve. Then pick **GitHub Copilot** and a model in the picker |

The chat then opens. The screen takes about 30 seconds to appear, because the memory plugin loads its search
engine; you may see some `cpuinfo` and `onnxruntime` lines first, which are harmless. The first run is the only
one that asks questions.

### 4. Pick a model that works

The assistant needs a model. Copilot is the default because the sign-in is one click.

- **GitHub Copilot.** Which models answer depends on your plan. A free account may reject the model the picker
  pre-selects with `The requested model is not supported`, even when Copilot's own list marks it enabled. If that
  happens, switch inside the chat:
  ```
  /model gpt-4.1 --global
  ```
  `gpt-4.1` and `gpt-4o-mini` answered on a free account. `--global` keeps the choice for next time.
- **Another provider.** Its API key is stored in OpenShell like the GitHub token, so the sandbox never sees it:
  ```bash
  container/kyverno --provider anthropic      # or openai, or nvidia
  ```
  The launcher asks for the key once. Then use `/model` to pick one of its models.

### 5. Talk to it

Just ask. For example (more in [`docs/capabilities.md`](docs/capabilities.md)):

```
what's my PR queue
explain PR #4181
which Dependabot PRs should I review and merge?
does #4172 need anything from me right now?
which stale PRs should I close or reassign?
tell me about issue #4512
```

It reads GitHub and answers. When you ask it to act (label, comment, approve), it asks you to confirm first.
Type `/help` for the chat commands.

## Everyday use

| To | Run |
|---|---|
| Start, or come back later | `container/kyverno` |
| Open a second chat at the same time | `container/kyverno` in another terminal |
| Open the dashboard | http://127.0.0.1:9219/kyverno?profile=kyverno (the launcher prints it; see [the dashboard](#the-dashboard)) |
| Leave | Close the chat. The sandbox keeps running, idle |
| Stop the sandbox | `openshell sandbox stop kyverno-assistant` (`container/kyverno` starts it again) |
| See whether it is running | `openshell sandbox list` |
| See what it contacted, and what was blocked | `openshell logs kyverno-assistant` |
| Update to a new version | `git pull`, then `container/kyverno --build --upgrade` (or `container/kyverno --upgrade` once images are published). Keeps your memory, history, sign-in and model |
| Replace your GitHub token | `bash -c 'read -rs -p "New GitHub token: " REPO_GITHUB_TOKEN; echo; export REPO_GITHUB_TOKEN; openshell provider update kyverno-repo-github --credential REPO_GITHUB_TOKEN'`, then open a new chat. Chats already open keep the old token |
| Use another model provider | `container/kyverno --provider anthropic` (or `openai`, `nvidia`) |
| Set up without opening the chat | `container/kyverno --no-attach` |

## Where your data lives

Your memory, chat history, notes, settings and the model sign-in live **inside the sandbox**, in the profile
folder `/opt/hermes-home/.hermes/profiles/kyverno`. They survive stopping and starting it, and
`container/kyverno --upgrade` carries them to a new image. Deleting the sandbox deletes them.

Your GitHub token is not in the sandbox: it lives in OpenShell, on your laptop. The Copilot sign-in token is in
the sandbox (it only grants access to Copilot's models).

What the sandbox can reach on the internet, and nothing else:

| Destination | Why |
|---|---|
| `api.github.com` (reads only) | The PR and issue data |
| The GitHub MCP server (`api.githubcopilot.com/mcp/`) | The tools the agent uses to look things up and to act, with your token added on the way out. The gateway lets through only the tools on the allowlist in `config.yaml` |
| GitHub Copilot's model service | The model, when you use Copilot. Only its inference paths, not `/mcp/` |
| `github.com` sign-in pages | Only the two device-code endpoints, for the Copilot sign-in |
| `github.com`, `codeload.github.com`, `raw.githubusercontent.com` (read-only) | Lets the agent's terminal read public code |
| `models.dev` (read-only) | The list of models for `/model` |
| A model provider you added | Only providers whose key you stored with `--provider` |

## How it stays safe

The agent cannot merge, and no single mechanism is trusted on its own. Five layers, and the ones that matter most
are enforced by OpenShell outside the sandbox, where the agent cannot edit them:

1. **The token has no merge permission** (Pull requests: write, but not Contents: write). GitHub itself refuses.
2. **The gateway checks every GitHub call.** On `api.github.com` it allows reads only and refuses merges, repository
   deletion and GraphQL mutations. On the GitHub MCP server it checks each tool call against the allowlist and
   refuses everything else, plus anything named like merge, delete or force-push, even inside a batched request.
3. **The tool allowlist in `config.yaml`**: the GitHub tool list has no merge tool.
4. **A hook** blocks any tool whose name looks like merge, delete or force-push.
5. **The network allowlist** denies everything not listed above.

Layers 1, 2 and 5 do not depend on any file inside the sandbox. Layers 3 and 4 do: the agent has a terminal and file
tools, so a manipulated agent could edit its own `config.yaml` (the hook scripts are read-only to it). Layers 1, 2 and
5 are what you rely on then.
Your token never enters the sandbox, so a prompt-injected agent cannot leak it. The details, including exactly what
was tested, are in [`docs/container.md`](docs/container.md).

## Why it is built this way

**Why a sandbox at all?** An assistant that reads issues and PR comments reads text written by strangers. A
sandbox means that even a successfully manipulated agent can only do what the sandbox allows: no access to your
files, no token to steal, only the listed hosts.

**Why one prebuilt image?** The agent is built from many moving parts (Hermes, Python packages, a memory plugin,
a search model). In a sandbox with no open internet, anything the agent tries to download or install the first
time it runs would fail, and some of those steps pop up a question the chat screen hides. So everything is installed
and checked when the image is built, including a full memory cycle run with the network switched off. A new
user's first run takes about a second of setup, and every machine runs identical bits.

**Why publish the image to ghcr.io?** `ghcr.io` is GitHub's container registry. Building the image on your own
laptop takes 15 to 30 minutes, downloads about 5 GB, and can break if a package was released since the last
person built it. Publishing it once from CI, from a tagged release, means a new maintainer just downloads it,
and an upgrade is a new tag. The workflow is `.github/workflows/container-image.yml`; it builds for Apple Silicon
and Intel and publishes one image. Until a release is published, use `--build`.

**Why does the first build take so long?** It downloads Hermes and its tools, the memory plugin, and a 64 MB
search model, then runs the proofs above. Later builds reuse Docker's cache and take seconds.

**Why no Slack or scheduled jobs yet?** Slack's tool runs under Docker, which a sandbox does not have, and the
scheduled jobs run inside Hermes' gateway, which is not started. They work in the
[host install](docs/host-install.md).

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `The requested model is not supported` | The model is not available on your Copilot plan. `/model gpt-4.1 --global` |
| `No LLM provider configured ... openrouter` | You picked a mixture-of-agents option that needs an OpenRouter key. Pick a normal model with `/model` |
| The chat looks frozen right after start | Give it 30 seconds. If it stays blank, press Enter once. If it still does nothing, run `container/kyverno --build --upgrade` |
| `could not pull ...` | No image is published yet. Use `container/kyverno --build` |
| The sandbox goes to `Error`, "UID or GID zero" | The image's default user must be 1000, not root. Rebuild with `--build` |
| `the OpenShell gateway is not connected` (or `No active gateway` from any `openshell` command) | OpenShell is installed but its background gateway is not running or not registered, or the only registered gateway is a leftover from an old OpenShell release (`openshell gateway list` shows `http://127.0.0.1:8080`). Remove the leftover (`openshell gateway remove <name>`, or `openshell gateway destroy` on an old CLI), then run OpenShell's installer: `curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/v0.1.3/install.sh \| OPENSHELL_VERSION=v0.1.3 OPENSHELL_ACK_BREAKING_UPGRADE=1 sh`. If the gateway is only stopped, `brew services start openshell`. `openshell status` should say Connected |
| `could not register the provider profile` | OpenShell holds an older copy of this project's profile from an earlier run. Start clean (nothing is rebuilt): `openshell sandbox delete kyverno-assistant`, `openshell provider delete kyverno-repo-github`, `openshell profile delete kyverno-repo-github`, then `container/kyverno --image kyverno-assistant:dev` (or without `--image` once an image is published). The launcher asks for your GitHub token again |
| `sandbox ... did not become Ready` | The launcher prints the sandbox's state and the last lines of its log. Retry from scratch: `openshell sandbox delete kyverno-assistant`, then run the launcher again |
| The build is very slow or runs out of memory | Docker Desktop's VM memory. Raise it in Settings → Resources (at least 4 GB) |
| `Docker Desktop ... is older than 4.60` | The sandbox needs a newer Docker Desktop. Update it |
| GitHub says the token is rejected | Wrong, expired or revoked: create a new one. A 404 means the token cannot see that repo (scope it to the repo, or have the org approve it) |

## Removing everything

```bash
openshell sandbox delete kyverno-assistant          # the sandbox and everything in it (memory, history, sign-in)
openshell provider delete kyverno-repo-github       # your stored GitHub token
openshell provider delete kyverno-anthropic         # model keys you added, if any (also kyverno-openai, kyverno-nvidia)
docker rmi kyverno-assistant:dev                    # the image, if you built it yourself
```

## What it does

| Area | Capabilities |
|---|---|
| **PR queue** | Fetches every open PR matching a focus (milestone, author, area or label) in one batched call, Dependabot PRs included. Builds a dependency graph, layers it into tiers (stacked PRs, generated-file conflicts, body references, closing-issue conflicts), then orders each tier by a precedence ladder and states the reason for every position. |
| **PR briefs** | Explains any PR: short by default, deeper on request (review threads, risk, suggested action, Slack and Discussions context). Open-ended questions are answered by looking things up. |
| **Merge gates** | Reports live e2e-gate status per target branch, kept separate from `ready-for-review`. |
| **Dependabot** | Reviews every open Dependabot PR and says which to merge now, fix first, review yourself, wait on, or close, citing call sites, release notes and Copilot's findings. |
| **Issues** | Classifies issues, maps issue and PR relationships, summarises progress, surfaces stale items, and runs the decide-table actions (label, close, assign, milestone, nudge, raise). |
| **Stale and author-blocked PRs** | Recommends close, reassign or needs-help, and checks status before a PR goes stale. |
| **PR actions** | Labels, comments, requests changes, approves, and brings a PR's branch up to date with its base, all with your own token. The branch update is a GitHub-API merge-update, not a git rebase, even when you ask for a rebase. |
| **Discussions** | Reads GitHub Discussions and drafts replies. Nothing is posted until you confirm. |
| **Memory** | Remembers your current focus and working style across sessions, plus past incidents, rejected PRs and contributor patterns, retrieved where relevant. |

**It cannot merge.** There is no merge tool in its toolset, and this is enforced in
[independent layers](#how-it-stays-safe). See [`docs/architecture.md`](docs/architecture.md).

## The dashboard

A browser board that shows what the agent just told you, linked, grouped and sortable, so you don't scroll the
chat or copy links by hand. It runs inside the sandbox, and the launcher forwards a port on your laptop to it and
prints the address:

```
http://127.0.0.1:9219/kyverno?profile=kyverno
```

Pick **Kyverno** in the sidebar under Plugins. It refreshes every 15 seconds. Keep it open next to the chat: it fills
when the agent answers a queue, stale-PR, issue-triage or Discussions request, not in the background.

| Tab | Shows |
|---|---|
| **Overview** | What is waiting on you, grouped by verdict (rescue, decide, review, close, triage…), the milestone and due date, gate status, recent actions. |
| **PRs / Issues / Discussions** | One row per item with a GitHub link, state (CI, merge state, size, labels) and the agent's verdict and reason. Switch views, filter by verdict, search, sort. |
| **Detail panel** | Summary, unresolved threads, a graph of related PRs and issues, and any drafted comment awaiting your confirmation, with a copy button. |
| **Activity** | Every action you confirmed (approvals, comments, nudges, closes, deferrals) with a timestamp and a link. |

The Kyverno tab is read-only. Confirming and acting still happen in the chat. It is reachable only from your own
laptop (the port is forwarded to `127.0.0.1` explicitly), and port 9219 is used so it does not clash with a Hermes
dashboard on 9119. Set `KYVERNO_DASHBOARD_PORT` to change it. Hermes protects the dashboard itself: a session token
that changes on every start, a check that the request's `Host` matches the address it listens on (against DNS
rebinding), and cross-origin requests only from localhost. It is still Hermes' whole dashboard, not just our tab: its
Settings and chat pages are served too, and the Settings pages can show what is in the sandbox's settings file, which
includes the Copilot sign-in token. Your GitHub token is not there. If you do not want it, stop it with
`openshell forward stop 9219` (the launcher starts it again next time you run it).

## Slack and scheduled jobs

These are not available in the sandbox yet. They work in the [host install](docs/host-install.md):

- **Slack**: talk to the assistant by mentioning it, and it can read and post in your maintainers channel.
- **Scheduled jobs**: a weekday review digest and two memory jobs (installed paused).

## Repository layout

```
container/               the sandbox: Dockerfile, launcher, policy, provider profiles (see container/README.md)
.github/workflows/       builds and publishes the sandbox image
distribution.yaml        install manifest: name, version, required env vars
SOUL.md                  the agent's identity and boundaries
config.yaml              model default, GitHub/Slack MCP servers, tool allowlist
scripts/install.sh       the host install: idempotent installer and sanity checks
scripts/update.sh        the host install: git pull, then re-run the installer
scripts/openshell.sh     the host install's sandboxed terminal: setup, policy, access requests, audit
policies/                OpenShell policy for the host install's sandboxed terminal
sandbox/                 Dockerfile of the host install's terminal sandbox image
hooks/                   pre_tool_call backstops
plugins/                 bundled Hermes plugins
skills/                  agent skills
cron/jobs.json           scheduled jobs (installed paused)
docs/                    design, deployment and usage docs
```

<details>
<summary><b>Details</b></summary>

**Core files**

- `config.yaml`: the model default, the GitHub and Slack MCP server declarations (`mcp_servers:`),
  and the hand-picked tool allowlist. Security-critical, so edit by hand only.
- `container/Dockerfile` and `container/setup-profile.sh`: build the sandbox image and do the one-time profile setup
  at build time.
- `scripts/install.sh`: the host install: profile install, credential check, gateway install, AGENTS.md cache
  seeding, toolset sanity checks.
- `cron/jobs.json`: a weekday review digest posted to Slack and two silent memory jobs
  (`kyverno-memory-sweep`, `kyverno-memory-consolidate`). All install paused.

**Hooks**

- `hooks/block-dangerous-tools.sh`: rejects any merge, delete-repo or force-push-shaped tool call.
- `hooks/block-mnemosyne-triples.sh`: restricts the memory plugin's `triple_add` to the exact facts
  this distribution writes.

**Plugins**

- `plugins/kyverno-fetch/`: `fetch_pr_candidates` and `fetch_file_diff_overlap`, one batched call
  over GitHub's GraphQL and REST APIs.
- `plugins/kyverno-sequencer/`: `sequence_prs`, a hard-dependency graph with cycle detection and
  topological layering into tiers.
- `plugins/kyverno-dashboard/`: the `update_dashboard` tool and the Kyverno tab in
  `hermes dashboard`.

**Skills**

| Skill | Purpose |
|---|---|
| `kyverno-context` | Live labels, CODEOWNERS and milestone lookup, plus Kyverno's codegen, CI split and e2e-gate facts |
| `pr-queue` | Merge-sequence recommendations and per-PR review briefs |
| `pr-actions` | Labels, comments, reviews and branch updates via your token |
| `dependabot-queue` | Dependabot PR verdicts |
| `issue-triage` | Issue classification, issue and PR relationships, progress, staleness |
| `issue-actions` | Issue label, close, assign, milestone, nudge and raise |
| `author-followup` | Stale and author-blocked PR decisions |
| `discussions` | Reads and answers GitHub Discussions, with confirmation before posting |
| `dashboard-sync` | Pushes presented results and confirmed actions to the dashboard |

</details>

## Further reading

| Doc | Contents |
|---|---|
| [`docs/container.md`](docs/container.md) | The sandbox in depth: what runs where, secrets, the network policy, what was verified, upgrades, a security review, how to update dependencies, publishing a release |
| [`docs/host-install.md`](docs/host-install.md) | Running without the sandbox: install, Slack setup, the review digest |
| [`docs/capabilities.md`](docs/capabilities.md) | A tour of what it can do, with example prompts |
| [`docs/deployment.md`](docs/deployment.md) | Install runbook and every environment variable (host install) |
| [`docs/architecture.md`](docs/architecture.md) | Design and security model |
| [`docs/workflow.md`](docs/workflow.md) | The target maintainer workflow and build plan |
