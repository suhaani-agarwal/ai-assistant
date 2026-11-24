---
# Shared component that gives the security triage agent a throwaway Kubernetes cluster to reproduce reports in.
# Import it next to shared/security-triage.md. Nothing is hosted: kind runs a one-node cluster inside the run's own
# GitHub machine, and it is gone when the run ends.
#
# How the agent reaches it: the agent's sandbox has no Docker and no route to the machine, so the cluster is driven
# through the mcp-scripts tools below. Those run on the machine, outside the sandbox, but each one runs a fixed
# program (kind, helm or kubectl) on checked arguments and never a shell command the agent wrote. kubectl reads
# manifests only from its stdin, never from a path on the machine: the agent's text, or a file the tool itself reads
# from the run's report manifests or the agent's scratch directory and nowhere else. The commands that would reach
# the machine itself (cp, proxy, port-forward, config, plugin) are refused.
#
# Every lab command is logged by the tools themselves, outside the sandbox where the agent cannot write, and the
# posting job lists those commands in the verdict comment, so the comment shows what really ran.
#
# Pods in the cluster can reach the internet, which pulls images and lets reports that need an outside listener be
# tested. Before this runs on real reports from the private repository, decide whether to cut that egress once the
# images are pulled.
import-schema:
  # The Helm repository and chart that install the project, and the namespace it goes into.
  helm_repo:
    type: string
    default: "https://kyverno.github.io/kyverno/"
  chart_name:
    type: string
    default: "kyverno"
  release_namespace:
    type: string
    default: "kyverno"

steps:
  - name: Start the lab cluster
    env:
      HELM_REPO: ${{ github.aw.import-inputs.helm_repo }}
      LAB_CHART: lab/${{ github.aw.import-inputs.chart_name }}
      LAB_NAMESPACE: ${{ github.aw.import-inputs.release_namespace }}
    run: |
      set -euo pipefail
      mkdir -p "$RUNNER_TEMP/security-triage-lab"
      cat > "$RUNNER_TEMP/security-triage-lab/lab.py" <<'PY'
      """The lab tools: create the cluster, install a release, run kubectl. Called by the mcp-scripts below."""
      import json, os, re, secrets, shlex, subprocess, sys, tempfile

      LAB = os.path.join(os.environ.get("RUNNER_TEMP") or "/tmp", "security-triage-lab")
      KUBECONFIG = os.path.join(LAB, "kubeconfig")
      # What ran, one JSON line per command, and which advisory and release it ran for. The tools run on the machine,
      # outside the agent's sandbox, which cannot write here.
      LOG = os.path.join(LAB, "commands.jsonl")
      STATE = os.path.join(LAB, "state.json")
      GHSA = re.compile(r"^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$")
      NAME = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
      RULE_VERBS = {"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "*"}
      RESOURCE = re.compile(r"^([a-z0-9*][a-z0-9-]*)(/[a-z]+)?(\.[a-z0-9][a-z0-9.-]*)?$")
      DATA_KEY = re.compile(r"^[-._a-zA-Z0-9]{1,253}$")
      CLUSTER = "lab"
      MAX_OUT = 20000
      VERSION = re.compile(r"^v?\d+\.\d+\.\d+(-(alpha|beta|rc)\.\d+)?$")
      MINOR = re.compile(r"^v?(\d+)\.(\d+)$")
      # A manifest must end with this line. The model can be stopped part way through a tool call and the call still
      # runs with what it had written; a cut-off manifest cannot carry the last line, so it is refused, not applied.
      END_MARKER = "# end"
      # Where `file` may point: the manifests copied from the reports, and the agent's scratch directory. A relative
      # path is under the first.
      FILE_ROOTS = ("/tmp/gh-aw/security-triage/manifests", "/tmp/gh-aw/security-triage/repro")
      MAX_FILE = 256000

      # kubectl subcommands the agent may run. Everything here acts on the cluster only.
      KUBECTL_VERBS = {
          "get", "describe", "apply", "create", "delete", "logs", "auth", "run", "exec", "patch", "label",
          "annotate", "rollout", "wait", "events", "api-resources", "api-versions", "explain", "version", "scale",
          "set", "replace", "top", "cluster-info",
      }
      # Flags that would point kubectl at another cluster or identity, or make it read files from the machine.
      FORBIDDEN_FLAGS = (
          "--kubeconfig", "--server", "-s", "--token", "--certificate-authority", "--client-certificate",
          "--client-key", "--context", "--cluster", "--user", "--username", "--password", "--insecure-skip-tls-verify",
          "--cache-dir", "-k", "--kustomize", "--from-file", "--from-env-file", "--env-file", "-R", "--recursive",
      )

      def out(code, text):
          text = text or ""
          if len(text) > MAX_OUT:
              text = "[... cut ...]\n" + text[-MAX_OUT:]
          print(f"exit {code}\n{text}")
          return code

      # Arguments that carry values inline. The log keeps the flag and key, not the value, as it may come from a report.
      VALUE_FLAGS = ("--from-literal", "--env", "--patch", "--overrides")

      def redact(tokens):
          # -p is the patch for `kubectl patch`, but --previous for `kubectl logs`.
          flags = VALUE_FLAGS + (("-p",) if tokens[:1] == ["patch"] else ())
          shown, hide_next = [], False
          for t in tokens:
              name, eq, value = t.partition("=")
              if hide_next:
                  shown.append("<value>")
                  hide_next = False
              elif name in flags and eq:
                  key = value.split("=", 1)[0] if name in ("--from-literal", "--env") and "=" in value else ""
                  shown.append(f"{name}={key + '=' if key else ''}<value>")
              elif t in flags:
                  shown.append(t)
                  hide_next = True
              else:
                  shown.append(t)
          return shown

      def state():
          try:
              with open(STATE) as f:
                  return json.load(f)
          except (OSError, ValueError):
              return {}

      def set_state(**kw):
          s = dict(state(), **kw)
          with open(STATE, "w") as f:
              json.dump(s, f)

      def log(command, code):
          s = state()
          try:
              with open(LOG, "a") as f:
                  f.write(json.dumps({"ghsa": s.get("ghsa", ""), "release": s.get("release", ""), "cmd": command,
                                      "exit": code}) + "\n")
          except OSError as e:
              # The command already ran; say so rather than lose its output.
              print(f"(not recorded in the lab log: {e})")

      def run(cmd, stdin=None, timeout=300):
          try:
              r = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout,
                                 env=dict(os.environ, KUBECONFIG=KUBECONFIG))
              return r.returncode, (r.stdout or "") + (r.stderr or "")
          except subprocess.TimeoutExpired:
              return 124, f"timed out after {timeout}s"

      def check_kubectl(args):
          """The argument list to run, or a ValueError saying why it is refused."""
          tokens = shlex.split(args or "")
          if tokens and tokens[0] == "kubectl":
              tokens = tokens[1:]
          if not tokens or tokens[0] not in KUBECTL_VERBS:
              raise ValueError(f"allowed subcommands: {', '.join(sorted(KUBECTL_VERBS))}")
          verb = tokens[0]
          # After `--` come the command and arguments for a container (exec, run), which kubectl does not read.
          flags = tokens[:tokens.index("--")] if "--" in tokens else tokens
          for i, t in enumerate(flags):
              name = t.split("=", 1)[0]
              if name in FORBIDDEN_FLAGS:
                  raise ValueError(f"{name} is not allowed in the lab")
              if "template-file" in t or "jsonpath-file" in t:
                  raise ValueError("templates must be given inline, not as a file")
              if verb == "logs" and name in ("-f", "--follow"):
                  raise ValueError("--follow would never return; use --tail or --since")
              if verb != "logs" and name in ("-f", "--filename"):
                  value = t.split("=", 1)[1] if "=" in t else (flags[i + 1] if i + 1 < len(flags) else "")
                  if value != "-":
                      raise ValueError("pass manifests through the stdin input with -f -, not as a file path")
              if verb != "logs" and t.startswith("-f") and not t.startswith("--") and len(t) > 2 and t != "-f-":
                  raise ValueError("pass manifests through the stdin input with -f -, not as a file path")
          return tokens

      def reads_manifest(tokens):
          """Whether kubectl reads a manifest from stdin (`-f -`), as opposed to stdin for a container (exec, run)."""
          flags = tokens[:tokens.index("--")] if "--" in tokens else tokens
          if flags and flags[0] == "logs":
              return False
          for i, t in enumerate(flags):
              if t in ("-f-", "-f=-", "--filename=-"):
                  return True
              if t in ("-f", "--filename") and i + 1 < len(flags) and flags[i + 1] == "-":
                  return True
          return False

      def read_manifest_file(path):
          """The text of a manifest file under FILE_ROOTS, or a ValueError saying why it is refused."""
          p = (path or "").strip()
          full = os.path.realpath(p if os.path.isabs(p) else os.path.join(FILE_ROOTS[0], p))
          if not any(full.startswith(os.path.realpath(r) + os.sep) for r in FILE_ROOTS):
              raise ValueError(f"file must be under {' or '.join(FILE_ROOTS)}")
          if not re.search(r"\.(ya?ml|json)$", full) or not os.path.isfile(full):
              raise ValueError(f"no .yaml, .yml or .json file at {p}")
          if os.path.getsize(full) > MAX_FILE:
              raise ValueError(f"file is over {MAX_FILE} bytes")
          with open(full) as f:
              return f.read()

      def chart_version(app_version, entries):
          """The chart version that ships app_version, from `helm search repo --versions -o json` entries."""
          stable = [e for e in entries if "-" not in e.get("app_version", "")]
          if app_version == "latest":
              return (stable or entries)[0]["version"] if entries else None
          m = MINOR.match(app_version)
          if m:
              # The newest patch of that minor release; Helm lists the newest chart first.
              for e in stable:
                  parts = e.get("app_version", "").lstrip("v").split(".")
                  if parts[:2] == list(m.groups()):
                      return e["version"]
              return None
          want = {app_version, app_version.lstrip("v"), "v" + app_version.lstrip("v")}
          for e in entries:
              if e.get("app_version") in want:
                  return e["version"]
          return None

      def create(k8s_version=""):
          if k8s_version and not VERSION.match(k8s_version):
              return out(2, "k8s_version must look like v1.34.0")
          run(["kind", "delete", "cluster", "--name", CLUSTER], timeout=120)
          cmd = ["kind", "create", "cluster", "--name", CLUSTER, "--kubeconfig", KUBECONFIG, "--wait", "120s"]
          if k8s_version:
              cmd += ["--image", "kindest/node:v" + k8s_version.lstrip("v")]
          code, text = run(cmd, timeout=300)
          if code == 0:
              code, nodes = run(["kubectl", "get", "nodes", "-o", "wide"])
              text += "\n" + nodes
          set_state(release="")
          log("lab-reset" + (f" {k8s_version}" if k8s_version else ""), code)
          return out(code, text)

      def install(version, values="", ghsa_id=""):
          version, ghsa_id = (version or "").strip(), (ghsa_id or "").strip()
          if not GHSA.match(ghsa_id):
              return out(2, "ghsa_id must be the GHSA ID of the advisory you are testing")
          if version != "latest" and not VERSION.match(version) and not MINOR.match(version):
              return out(2, "version must be `latest`, a release such as v1.16.1, or a minor such as v1.16 for its newest patch")
          if len(values or "") > 20000:
              return out(2, "values are limited to 20000 characters")
          chart, ns = os.environ["LAB_CHART"], os.environ["LAB_NAMESPACE"]
          code, text = run(["helm", "search", "repo", chart, "--versions", "-o", "json"], timeout=60)
          if code:
              return out(code, text)
          entries = json.loads(text or "[]")
          cv = chart_version(version, entries)
          if not cv:
              known = ", ".join(e.get("app_version", "") for e in entries[:15])
              return out(2, f"no chart ships {version}. Recent releases: {known}")
          run(["helm", "uninstall", "kyverno-lab", "-n", ns, "--wait", "--kubeconfig", KUBECONFIG], timeout=300)
          cmd = ["helm", "install", "kyverno-lab", chart, "--version", cv, "-n", ns, "--create-namespace",
                 "--wait", "--timeout", "8m", "--kubeconfig", KUBECONFIG]
          with tempfile.NamedTemporaryFile("w", suffix=".yaml", dir=LAB, delete=False) as f:
              f.write(values or "")
          if values:
              cmd += ["-f", f.name]
          code, text = run(cmd, timeout=600)
          _, pods = run(["kubectl", "get", "pods", "-n", ns, "-o", "wide"])
          app = next((e.get("app_version") for e in entries if e.get("version") == cv), "")
          set_state(ghsa=ghsa_id, release=app if code == 0 else "")
          log(f"lab-install {version} (chart {cv}, release {app})" + (" with Helm values" if values else ""), code)
          return out(code, f"chart {chart} {cv} (release {app})\n{text}\n{pods}")

      def parse_rules(text):
          """Role rules from `verbs:resources; ...`, e.g. `create,get:configmaps,policies.kyverno.io`."""
          rules = []
          for part in [p.strip() for p in (text or "").split(";") if p.strip()]:
              if ":" not in part:
                  raise ValueError(f"{part!r}: write each rule as verbs:resources")
              verbs_text, resources_text = part.split(":", 1)
              verbs = [v.strip() for v in verbs_text.split(",") if v.strip()]
              if not verbs or not set(verbs) <= RULE_VERBS:
                  raise ValueError(f"{part!r}: verbs must be from {', '.join(sorted(RULE_VERBS))}")
              by_group = {}
              for r in [r.strip() for r in resources_text.split(",") if r.strip()]:
                  if not RESOURCE.match(r):
                      raise ValueError(f"{r!r} is not a resource, e.g. configmaps or policies.kyverno.io")
                  name, _, group = r.partition(".")
                  by_group.setdefault(group, []).append(name)
              if not by_group:
                  raise ValueError(f"{part!r}: name at least one resource")
              rules += [{"apiGroups": [g], "resources": names, "verbs": verbs} for g, names in by_group.items()]
          if not rules:
              raise ValueError("give at least one rule")
          return rules

      def tenant(namespace="", rules="", other_namespace="", user="", canary_name="", canary_key=""):
          """The usual setup for a report about a namespaced user: that user with only the given permissions in its
          namespace, a canary value in another namespace, and what the user can and cannot do. The names default to
          probe-*, and are set to the report's own when its manifests name them, so they apply unchanged."""
          ns, other, user = namespace or "probe-tenant", other_namespace or "probe-other", user or "probe-user"
          name, key = canary_name or "probe-canary", canary_key or "value"
          try:
              for n in (ns, other, user, name):
                  if not NAME.match(n):
                      raise ValueError(f"{n!r} is not a valid Kubernetes name")
              if not DATA_KEY.match(key):
                  raise ValueError(f"{key!r} is not a valid data key")
              if len(user) > 55:
                  raise ValueError("user is limited to 55 characters, so its Role and RoleBinding names fit")
              if ns == other:
                  raise ValueError("the other namespace must differ from the user's")
              parsed = parse_rules(rules)
          except ValueError as e:
              return out(2, str(e))
          canary = "canary-" + secrets.token_hex(4)
          objects = [
              {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns}},
              {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": other}},
              {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": user, "namespace": ns}},
              {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
               "metadata": {"name": f"{user}-role", "namespace": ns}, "rules": parsed},
              {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
               "metadata": {"name": f"{user}-binding", "namespace": ns},
               "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": f"{user}-role"},
               "subjects": [{"kind": "ServiceAccount", "name": user, "namespace": ns}]},
              {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name, "namespace": other},
               "data": {key: canary}},
              {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name, "namespace": other},
               "stringData": {key: canary}},
          ]
          code, applied = run(["kubectl", "--request-timeout=90s", "apply", "-f", "-"],
                              stdin=json.dumps({"apiVersion": "v1", "kind": "List", "items": objects}), timeout=150)
          log(f"lab-tenant namespace={ns} other_namespace={other} user={user} canary={other}/{name}:{key} "
              f"rules={rules.strip()}", code)
          if code:
              return out(code, applied)
          as_user = f"system:serviceaccount:{ns}:{user}"
          checks = [(v, r, ns) for rule in parsed for v in rule["verbs"] if v != "*"
                    for r in [f"{n}.{rule['apiGroups'][0]}" if rule["apiGroups"][0] else n for n in rule["resources"]]][:20]
          checks += [("get", "configmaps", other), ("get", "secrets", other), ("list", "secrets", "")]
          lines = []
          for verb, resource, where in checks:
              scope = ["-n", where] if where else ["--all-namespaces"]
              # can-i exits 1 for "no", so the answer is read from its output; anything else is an error, not a result.
              code, answer = run(["kubectl", "auth", "can-i", verb, resource, *scope, f"--as={as_user}"], timeout=60)
              first = answer.strip().splitlines()[0] if answer.strip() else ""
              if first not in ("yes", "no"):
                  return out(code or 1, f"the user was created, but `auth can-i {verb} {resource}` failed:\n{answer}")
              lines.append(f"  {first:4} {verb} {resource} " + (f"-n {where}" if where else "--all-namespaces"))
          return out(0, f"act as this user with: --as={as_user}\n"
                        f"canary value: {canary}, under key `{key}` in ConfigMap {other}/{name} and Secret {other}/{name}\n"
                        "what the user can do (kubectl auth can-i):\n" + "\n".join(lines) + "\n\n" + applied)

      def kubectl(args, stdin="", file=""):
          try:
              tokens = check_kubectl(args)
              if file:
                  if stdin:
                      raise ValueError("give the manifest as stdin or as file, not both")
                  if not reads_manifest(tokens):
                      raise ValueError("file is for a manifest: use it with -f -")
                  stdin = read_manifest_file(file)
          except ValueError as e:
              return out(2, str(e))
          # A file is read whole by this tool, so only typed stdin can be cut off.
          if stdin and not file and reads_manifest(tokens):
              # Only trailing whitespace is ignored: an indented `# end` can be the last line of a cut-off block.
              lines = [l.rstrip() for l in stdin.splitlines() if l.strip()]
              if not lines or lines[-1] != END_MARKER:
                  return out(2, f"stdin does not end with the line `{END_MARKER}`, so it was probably cut off before "
                                "the end. Nothing was applied. Send the whole manifest again, ending with that line.")
          code, text = run(["kubectl", "--request-timeout=90s", *tokens], stdin=stdin or None, timeout=150)
          log("kubectl " + shlex.join(redact(tokens)) + (f" < {os.path.basename(file)}" if file else " < stdin" if stdin else ""), code)
          return out(code, text)

      def main(argv):
          cmd = argv[0] if argv else ""
          env = os.environ.get
          if cmd == "create":
              return create(env("INPUT_K8S_VERSION", ""))
          if cmd == "install":
              return install(env("INPUT_VERSION", ""), env("INPUT_VALUES", ""), env("INPUT_GHSA_ID", ""))
          if cmd == "tenant":
              return tenant(env("INPUT_NAMESPACE", ""), env("INPUT_RULES", ""), env("INPUT_OTHER_NAMESPACE", ""),
                            env("INPUT_USER", ""), env("INPUT_CANARY_NAME", ""), env("INPUT_CANARY_KEY", ""))
          if cmd == "kubectl":
              return kubectl(env("INPUT_ARGS", ""), env("INPUT_STDIN", ""), env("INPUT_FILE", ""))
          return out(2, f"unknown command {cmd!r}")

      if __name__ == "__main__" and os.environ.get("SECURITY_TRIAGE_NO_MAIN") != "1":
          # Always exit 0 so the agent sees the output; the first line carries the real exit code.
          main(sys.argv[1:])
      PY
      helm repo add lab "$HELM_REPO" >/dev/null
      helm repo update lab >/dev/null
      python3 -I "$RUNNER_TEMP/security-triage-lab/lab.py" create

# After the agent: keep the command log for the posting job, which lists it in the verdict comment.
post-steps:
  - name: Keep the lab command log
    if: always()
    uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
    with:
      name: security-triage-lab-log
      path: ${{ runner.temp }}/security-triage-lab/commands.jsonl
      retention-days: 1
      if-no-files-found: ignore

mcp-scripts:
  lab-reset:
    description: >-
      Delete the lab cluster and create a fresh, empty one (about a minute), so nothing from one attempt carries into
      the next. Optionally pick the Kubernetes version.
    inputs:
      k8s_version:
        type: string
        required: false
        description: "Kubernetes version for the node, e.g. v1.34.0. Empty for kind's default."
    run: python3 -I "$RUNNER_TEMP/security-triage-lab/lab.py" create
    timeout: 360
  lab-install:
    description: >-
      Install a release of the project into the lab cluster with Helm, replacing any release already there, and
      wait until it is ready (a few minutes). Returns Helm's output and the project's pods.
    inputs:
      ghsa_id:
        type: string
        required: true
        description: "The GHSA ID of the advisory you are testing. The lab records which advisory each command was for."
      version:
        type: string
        required: true
        description: "`latest`, the application release to install (e.g. v1.16.1), or a minor (e.g. v1.16) for its newest patch."
      values:
        type: string
        required: false
        description: "Optional Helm values as YAML, for reports that need a non-default setting or flag."
    run: python3 -I "$RUNNER_TEMP/security-triage-lab/lab.py" install
    env:
      LAB_CHART: lab/${{ github.aw.import-inputs.chart_name }}
      LAB_NAMESPACE: ${{ github.aw.import-inputs.release_namespace }}
    timeout: 660
  lab-tenant:
    description: >-
      The usual setup for a report about a namespaced user, in one call: a service account with only the permissions
      you give, in its namespace, and a canary value in a ConfigMap and a Secret in another namespace. Returns the
      --as value, the canary value and `auth can-i` results showing what the user can and cannot do.
    inputs:
      rules:
        type: string
        required: true
        description: >-
          The user's permissions in its namespace, as verbs:resources separated by `;`, e.g.
          `create,get,list,update,delete:policies.kyverno.io,configmaps`. Give exactly what the report says the user has.
      namespace:
        type: string
        required: false
        description: "The user's namespace: the one the report's manifests use, if they name one. Default probe-tenant."
      other_namespace:
        type: string
        required: false
        description: >-
          The namespace the user should not reach, which holds the canary: the one the report's manifests read from,
          if they name one. Default probe-other.
      user:
        type: string
        required: false
        description: "The service account name: the report's, if it names one. Default probe-user."
      canary_name:
        type: string
        required: false
        description: >-
          The name of the ConfigMap and Secret that hold the canary: the object the report's manifests read, if they
          name one. Default probe-canary.
      canary_key:
        type: string
        required: false
        description: "The data key that holds the canary: the key the report's manifests read, if they name one. Default value."
    run: python3 -I "$RUNNER_TEMP/security-triage-lab/lab.py" tenant
    timeout: 180
  lab-kubectl:
    description: >-
      Run one kubectl command against the lab cluster, e.g. `apply -f -` with the manifest in stdin, `get pods -A`,
      `auth can-i get secrets -n other --as=system:serviceaccount:tenant:probe-user`, or `logs -n kyverno deploy/x`.
      Act as a user with --as. A manifest goes in stdin, or as `file` for one of the report's manifest files or one
      in your scratch directory. Returns the exit code and output.
    inputs:
      args:
        type: string
        required: true
        description: "The kubectl arguments, without the word kubectl."
      stdin:
        type: string
        required: false
        description: "Text piped to kubectl. For a manifest (`-f -`), its last line must be `# end`, unindented."
      file:
        type: string
        required: false
        description: >-
          Instead of stdin, a manifest file to pipe to kubectl with `-f -`: a report manifest as listed (e.g.
          GHSA-xxxx-xxxx-xxxx/01-ClusterPolicy-name.yaml), or a full path in your scratch directory. No `# end` needed.
    run: python3 -I "$RUNNER_TEMP/security-triage-lab/lab.py" kubectl
    timeout: 180
---

## The lab

You also have a throwaway Kubernetes cluster for this run, built only for reproducing reports. Nothing in it is
real, and it is deleted when the run ends. Use it whenever a report depends on a running cluster: permissions and
namespaces, the admission webhook, the background, reports or cleanup controllers, `apiCall` or service calls, or a
controller crashing. Use the CLI for what the CLI can show on its own.

- `lab-reset` gives you a fresh empty cluster. It already ran once before you started, so the cluster exists, but
  nothing is installed in it yet.
- `lab-install` installs a release with Helm, for the advisory you name in `ghsa_id`: a release such as `v1.16.1`, a
  minor such as `v1.16` for its newest patch, or `latest`. Its output names the release it installed. Pass Helm values
  when the report needs a non-default setting, and say in your verdict which ones you set and why.
- `lab-tenant` sets up a namespaced user and a canary value in a namespace it should not reach, in one call.
- `lab-kubectl` runs one kubectl command. For a manifest from the report, use `-f -` with `file` set to its listed
  path, and do not retype it. The same works for a file you wrote in your scratch directory, so you can apply it
  again on another release without sending it twice. Otherwise put the manifest in `stdin` with `-f -`, and end
  `stdin` with the line `# end`: if that line is missing, the input was cut off and nothing is applied, so send it
  again in full.

For each release the advisory steps ask you to test:

1. `lab-install` it. Then, for a report about a namespaced user, call `lab-tenant` with exactly the permissions the
   report says the user has, and with the namespaces, user and object its manifests use, so they apply unchanged. The
   canary makes "the value appeared" or "it changed" something you can see, not something you infer. Read its
   `auth can-i` results: if the user can already reach the other namespace, the report's claim proves nothing. Add
   anything else the report needs with `lab-kubectl`.
2. Follow the report's steps as that user and record what you observe: denials, the canary showing up where it
   should not, a resource changed, a controller restarting (`get pods -n <namespace>` restart counts and
   `logs --previous`).
3. `lab-reset` before the next release and before the next advisory.

The lab records every command it runs, and the verdict comment lists them next to your evidence.

If a report needs something the lab cannot provide (a cloud provider, several nodes, an unreleased build, the
public internet), say exactly what was missing in your verdict and call `report_missing_tool` naming it, then
reason from what you could test.
