---
# Shared component that gives the security triage agent a throwaway Kubernetes cluster to reproduce reports in.
# Import it next to shared/security-triage.md. Nothing is hosted: kind runs a one-node cluster inside the run's own
# GitHub machine, and it is gone when the run ends.
#
# How the agent reaches it: the agent's sandbox has no Docker and no route to the machine, so the cluster is driven
# through the mcp-scripts tools below. Those run on the machine, outside the sandbox, but each one runs a fixed
# program (kind, helm or kubectl) on checked arguments and never a shell command the agent wrote. kubectl reads
# manifests only from the agent's input, never from a path on the machine, and the commands that would reach the
# machine itself (cp, proxy, port-forward, config, plugin) are refused.
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
      import json, os, re, shlex, subprocess, sys, tempfile

      LAB = os.path.join(os.environ.get("RUNNER_TEMP") or "/tmp", "security-triage-lab")
      KUBECONFIG = os.path.join(LAB, "kubeconfig")
      CLUSTER = "lab"
      MAX_OUT = 20000
      VERSION = re.compile(r"^v?\d+\.\d+\.\d+(-(alpha|beta|rc)\.\d+)?$")

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

      def chart_version(app_version, entries):
          """The chart version that ships app_version, from `helm search repo --versions -o json` entries."""
          if app_version == "latest":
              stable = [e for e in entries if "-" not in e.get("app_version", "")]
              return (stable or entries)[0]["version"] if entries else None
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
          return out(code, text)

      def install(version, values=""):
          version = (version or "").strip()
          if version != "latest" and not VERSION.match(version):
              return out(2, "version must be `latest` or a release such as v1.16.1")
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
          return out(code, f"chart {chart} {cv}\n{text}\n{pods}")

      def kubectl(args, stdin=""):
          try:
              tokens = check_kubectl(args)
          except ValueError as e:
              return out(2, str(e))
          code, text = run(["kubectl", "--request-timeout=90s", *tokens], stdin=stdin or None, timeout=150)
          return out(code, text)

      def main(argv):
          cmd = argv[0] if argv else ""
          env = os.environ.get
          if cmd == "create":
              return create(env("INPUT_K8S_VERSION", ""))
          if cmd == "install":
              return install(env("INPUT_VERSION", ""), env("INPUT_VALUES", ""))
          if cmd == "kubectl":
              return kubectl(env("INPUT_ARGS", ""), env("INPUT_STDIN", ""))
          return out(2, f"unknown command {cmd!r}")

      if __name__ == "__main__" and os.environ.get("SECURITY_TRIAGE_NO_MAIN") != "1":
          # Always exit 0 so the agent sees the output; the first line carries the real exit code.
          main(sys.argv[1:])
      PY
      helm repo add lab "$HELM_REPO" >/dev/null
      helm repo update lab >/dev/null
      python3 -I "$RUNNER_TEMP/security-triage-lab/lab.py" create

mcp-scripts:
  lab-reset:
    description: >-
      Delete the lab cluster and create a fresh, empty one (about a minute). Use it before switching releases and
      between advisories, so nothing from one attempt leaks into the next. Optionally pick the Kubernetes version.
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
      version:
        type: string
        required: true
        description: "`latest`, or the application release to install, e.g. v1.16.1."
      values:
        type: string
        required: false
        description: "Optional Helm values as YAML, for reports that need a non-default setting or flag."
    run: python3 -I "$RUNNER_TEMP/security-triage-lab/lab.py" install
    env:
      LAB_CHART: lab/${{ github.aw.import-inputs.chart_name }}
      LAB_NAMESPACE: ${{ github.aw.import-inputs.release_namespace }}
    timeout: 660
  lab-kubectl:
    description: >-
      Run one kubectl command against the lab cluster, e.g. `apply -f -` with the manifest in stdin, `get pods -A`,
      `auth can-i get secrets -n victim --as=system:serviceaccount:tenant:attacker`, or `logs -n kyverno deploy/x`.
      Impersonate users with --as. Manifests go in stdin, never as a file path. Returns the exit code and output.
    inputs:
      args:
        type: string
        required: true
        description: "The kubectl arguments, without the word kubectl."
      stdin:
        type: string
        required: false
        description: "Text piped to kubectl, for `-f -`."
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
- `lab-install` installs a release with Helm: `latest`, or the version the report names. Pass Helm values when the
  report needs a non-default setting, and say in your verdict which ones you set and why.
- `lab-kubectl` runs one kubectl command. Put manifests in `stdin` with `-f -`. Act as a restricted user with
  `--as=system:serviceaccount:<namespace>:<name>` after creating that service account and its Role and RoleBinding.

How to use it:

1. Build only what the report needs: the attacker's account with exactly the permissions the report says they
   have, a separate namespace for anything the attacker should not reach, and a canary value of your own (for
   example a Secret or ConfigMap holding `canary-<random>`) so that "it leaked" or "it changed" is something you can
   see, not something you infer. Check the attacker's limits with `auth can-i` before the attack.
2. Install the version the report names, run the attack as the report describes, and record what you observe:
   denials, the canary showing up where it should not, a resource changed, a controller restarting
   (`get pods -n <namespace>` restart counts and `logs --previous`).
3. Then `lab-reset`, install `latest`, and repeat, so you can say whether it still happens. If the report names a
   fixed release, trying that one too is the strongest check.
4. `lab-reset` before moving to the next advisory.

If a report needs something the lab cannot provide (a cloud provider, several nodes, an unreleased build, the
public internet), say exactly what was missing in your verdict and call `report_missing_tool` naming it, then
reason from what you could test.
