# Automatically Unpublish NPM Packages Published Outside CI

![Image](https://github.com/user-attachments/assets/973be7b2-902c-47df-93b6-3fff475e3976)

This is a **Tangent plugin** that protects your NPM organization by detecting and automatically unpublishing package versions that were **not published through your approved CI workflows**.

Tangent is a security data pipeline built for enrichment, detection, and automation.
📘 **Docs:** [https://docs.telophasehq.com](https://docs.telophasehq.com)

This plugin monitors all package publishes in real time, and takes action when a version appears that wasn’t created by CI.

## How it works

* Watches your NPM organization for publish events
* Verifies each version against your GitHub Actions workflow
* If a publish **did not come from CI**, the plugin:

  * Sends an alert to Slack
  * Automatically **unpublishes the version**

This protects your packages against:

* Manual `npm publish` mistakes
* Compromised developer tokens
* CI bypass attempts / supply chain tampering


## How to Use

### 1. Setup

```bash
./setup.sh
```

### 2. Compile Plugin

```bash
tangent plugin compile --config tangent.yaml
```

### 3. Run Tests

```bash
tangent plugin test --config tangent.yaml
```

### 4. Run the Pipeline

```bash
tangent run --config tangent.yaml
```

---

## Configuration

In your `tangent.yaml`, configure:

```yaml
plugins:
  npmcicorrelationdetector:
    module_type: go
    path: .
    config:
      slack_channel: "slack-app-testing"
      unpublish: true
      "@telophasehq/tangent-break-js":
        repo: "telophasehq/example-github"
        workflow: "release.yml"
```

* `slack_channel`: where alerts go
* `unpublish`: toggle automatic cleanup
* Per-package GitHub repo + workflow to validate publish origin

