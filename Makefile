SHELL := /bin/bash
.DEFAULT_GOAL := help

IMAGE ?= assistant
TAG ?= dev
DOCKERFILE := container/Dockerfile
SHELLCHECK_IMAGE := koalaman/shellcheck@sha256:bb596a0d169b85ddd81d8b6d3a2ff6d5baf5fca10b97f575ebc647c3dff62b3d
ORG ?= kyverno
HADOLINT_IMAGE := hadolint/hadolint@sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d
TRIVY_IMAGE := aquasec/trivy@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222
SHELL_SCRIPTS := install.sh scripts/adopt-ci.sh container/assistant container/assistant-docker container/lib.sh container/kyverno-start container/kyverno-main container/kyverno-digest container/kyverno-env \
	container/setup-profile.sh container/restore-state.sh container/verify-image.sh container/hooks/require-sandbox-terminal.sh \
	container/assistant-workspace container/toolchains/go.sh container/toolchains/node.sh container/toolchains/kyverno-tools.sh tests/image/run.sh

.PHONY: help lint lint-shell lint-dockerfile lint-providers image test unit image-check scan check run

help: ## Show available development commands
	@awk 'BEGIN { FS = ":.*## " } /^[a-zA-Z0-9_-]+:.*## / { printf "  %-18s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

lint: lint-shell lint-dockerfile lint-providers ## Run the repository linters

lint-shell: ## Lint shell scripts with the pinned ShellCheck image
	docker run --rm -v "$(CURDIR)":/mnt -w /mnt $(SHELLCHECK_IMAGE) $(SHELL_SCRIPTS)

lint-dockerfile: ## Lint the sandbox Dockerfile with the pinned Hadolint image
	docker run --rm -i $(HADOLINT_IMAGE) hadolint --ignore DL3008 --failure-threshold warning - < $(DOCKERFILE)

lint-providers: ## Fail if a provider profile allows every path (read-write or full) instead of named ones
	@! grep -nE '^[[:space:]]*access:[[:space:]]*(read-write|full)' container/providers/*.yaml \
		|| { echo "provider profiles must list the paths they allow (rules:), not use access: read-write/full"; exit 1; }

image: ## Build the local sandbox image (override IMAGE and TAG as needed)
	docker build -f $(DOCKERFILE) -t $(IMAGE):$(TAG) --build-arg ORG_PACK=$(ORG) .

test: image ## Build and run the Dockerfile's offline integration checks

unit: ## Run the plugin, hook and workflow-script tests (Python and PyYAML only)
	python3 -m unittest discover -s tests/plugins && python3 -m unittest discover -s tests/hooks && python3 -m unittest discover -s tests/workflows

image-check: image ## Build the image and run tests/image/run.sh against it
	tests/image/run.sh $(IMAGE):$(TAG)

scan: image ## Build and scan the local image for fixable critical vulnerabilities
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		-v kyverno-assistant-trivy-cache:/root/.cache/trivy $(TRIVY_IMAGE) \
		image --scanners vuln --severity CRITICAL --ignore-unfixed --exit-code 1 $(IMAGE):$(TAG)

check: lint unit image-check ## Run linters and the Dockerfile integration checks

run: image ## Build and launch the sandbox using the local image
	ASSISTANT_IMAGE=$(IMAGE):$(TAG) ./container/assistant $(ARGS)
