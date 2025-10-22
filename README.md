### README: Using the Tangent Plugins in your Go project

This repository contains Go mappers that convert various event sources into OCSF v1.5.0 types:

- **Zeek**: `conn` and `dns` logs → OCSF Network/DNS activity
- **AWS**: CloudTrail and Security Hub findings → OCSF API/Vulnerability events

The code exports small, focused helpers under `zeek/mappers`, `ocsf-go/mappers`, and lightweight JSON helpers under `*/tangenthelpers`.

### Supported outputs
- **OCSF types**: `github.com/telophasehq/go-ocsf/ocsf/v1_5_0`

### Importing the modules

This is a multi-module repository with local module names (`zeek`, `ocsf-go`). Choose one of the options below:

#### Option A: Use a Go workspace (recommended for local development)

1) Initialize a workspace (or add to an existing one) from your app’s root:
```bash
go work init
go work use PATH/TO/tangent-plugins/aws
go work use PATH/TO/tangent-plugins/zeek
```

2) Import with aliases to avoid the shared `mappers` package name:
```go
import (
    awsmappers  "ocsf-go/mappers"
    zeekmappers "zeek/mappers"
    v1_5_0      "github.com/telophasehq/go-ocsf/ocsf/v1_5_0"
)
```

3) Build as usual; the workspace will resolve the local modules.

#### Option B: Use `replace` in your app’s `go.mod` (no workspace required)

Add local path replaces:
```go
require (
    ocsf-go v0.0.0
    zeek    v0.0.0
)

replace ocsf-go => PATH/TO/tangent-plugins/aws
replace zeek    => PATH/TO/tangent-plugins/zeek
```

Then import as:
```go
import (
    awsmappers  "ocsf-go/mappers"
    zeekmappers "zeek/mappers"
)
```

Note: If/when you publish these modules, switch `module` paths in `aws/go.mod` and `zeek/go.mod` to your VCS (e.g., `github.com/<org>/tangent-plugins/aws` and `.../zeek`), then remove the `replace`/workspace steps.

### Minimal usage examples

#### Zeek: conn.log → OCSF NetworkActivity
```go
package main

import (
    "fmt"
    zeekmappers "zeek/mappers"
    v1_5_0 "github.com/telophasehq/go-ocsf/ocsf/v1_5_0"
)

func main() {
    // Example Zeek conn JSON (RFC3339Nano times)
    line := []byte(`{
        "ts":"2024-07-16T16:29:40.123456789Z",
        "_write_ts":"2024-07-16T16:29:41.000000000Z",
        "uid":"C8j0LZ2Q3i1",
        "id.orig_h":"10.0.0.5","id.orig_p":44321,
        "id.resp_h":"93.184.216.34","id.resp_p":443,
        "proto":"tcp"
    }`)

    evt, err := zeekmappers.MapZeekConn(line)
    if err != nil {
        panic(err)
    }
    // evt is *v1_5_0.NetworkActivity
    fmt.Println(evt.ClassUid, evt.TypeUid)
    _ = v1_5_0.NetworkActivity{}
}
```

#### Zeek: dns.log → OCSF DNSActivity
```go
package main

import (
    "fmt"
    zeekmappers "zeek/mappers"
)

func main() {
    line := []byte(`{
        "_path":"dns",
        "_system_name":"sensor-1",
        "_write_ts":"2024-07-16T16:30:01.000000000Z",
        "ts":"2024-07-16T16:30:00.123456789Z",
        "uid":"D4kJz1",
        "proto":"udp",
        "id.orig_h":"10.0.0.5","id.orig_p":50123,
        "id.resp_h":"1.1.1.1","id.resp_p":53,
        "query":"example.com",
        "qtype":1,
        "answers":["93.184.216.34"],
        "TTLs":[60]
    }`)

    evt, err := zeekmappers.MapZeekDNS(line)
    if err != nil {
        panic(err)
    }
    fmt.Println(evt.Query.GetHostname(), evt.Rcode)
}
```

#### AWS: CloudTrail → OCSF APIActivity
```go
package main

import (
    "fmt"
    awsmappers "ocsf-go/mappers"
)

func main() {
    ct := []byte(`{
      "eventVersion":"1.08",
      "eventID":"abcd-1234",
      "eventTime":"2024-07-16T16:31:00Z",
      "eventSource":"ec2.amazonaws.com",
      "eventName":"StartInstances",
      "awsRegion":"us-east-1",
      "eventType":"AwsApiCall",
      "sourceIPAddress":"203.0.113.10",
      "userAgent":"aws-cli/2.x",
      "recipientAccountId":"123456789012",
      "userIdentity":{"type":"IAMUser","principalId":"AID...","arn":"arn:aws:iam::123456789012:user/alice","userName":"alice"}
    }`)

    evt, err := awsmappers.CloudtrailToOCSF(ct)
    if err != nil {
        panic(err)
    }
    // evt is *ocsf.APIActivity
    fmt.Println(*evt.TypeName, *evt.Status)
}
```

#### AWS: Security Hub → OCSF VulnerabilityFinding
- Unpack EventBridge events containing `detail.findings`:
```go
package main

import (
    "fmt"
    awsmappers "ocsf-go/mappers"
)

func main() {
    eb := []byte(`{
      "detail-type":"Security Hub Findings - Imported",
      "detail":{"findings":[ { "Id":"sh-1", "Title":"Example", "Severity":{"Label":"HIGH"}, "CreatedAt":"2024-07-16T16:32:00Z", "UpdatedAt":"2024-07-16T16:33:00Z", "Description":"...", "Resources":[{"Type":"AwsEc2Instance","Id":"i-123"}] } ]}
    }`)

    findings, err := awsmappers.UnpackSHFindings(eb)
    if err != nil {
        panic(err)
    }
    for _, f := range findings {
        fmt.Println(f.FindingInfo.Uid, f.SeverityId)
    }
}
```

- Or map a single `types.AwsSecurityFinding`:
```go
package main

import (
    "fmt"
    awsmappers "ocsf-go/mappers"
    "github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

func main() {
    title := "Example"
    created := "2024-07-16T16:32:00Z"
    updated := "2024-07-16T16:33:00Z"
    id := "finding-1"
    sev := &types.Severity{Label: types.SeverityLabelHigh}

    f := types.AwsSecurityFinding{
        Id:        &id,
        Title:     &title,
        CreatedAt: &created,
        UpdatedAt: &updated,
        Severity:  sev,
        Types:     []string{"Software and Configuration Checks/Vulnerabilities/CVE"},
        Resources: []types.Resource{{Type: strPtr("AwsEc2Instance"), Id: strPtr("i-123")}},
    }

    out, err := awsmappers.SecurityHubToOCSF(f)
    if err != nil {
        panic(err)
    }
    fmt.Println(*out.ActivityName, out.SeverityId)
}

func strPtr(s string) *string { return &s }
```

### JSON helper utilities (optional)

- `aws/tangenthelpers` and `zeek/tangenthelpers` expose a tiny set of helpers:
  - **Has**: quick existence check using JSON parser
  - **GetString**: retrieve a string by path
  - **ToRaw**: `any` → `json.RawMessage`

```go
import awshelpers "ocsf-go/tangenthelpers"
import zeekhelpers "zeek/tangenthelpers"
```

### Notes
- **OCSF version**: All outputs use `github.com/telophasehq/go-ocsf/ocsf/v1_5_0`.
- **Go version**: Developed with Go 1.24 toolchain.
- If you later publish these modules, set the `module` lines in `aws/go.mod` and `zeek/go.mod` to your VCS paths to enable `go get` without `replace`/workspaces.
- If you hit mismatched module path errors, prefer Option A (workspace) or Option B (`replace`).
- When parsing Zeek logs, ensure timestamps are RFC3339Nano as expected by the mappers.
- For Security Hub, the single-finding mapper uses `github.com/aws/aws-sdk-go-v2/service/securityhub/types` inputs.
- For CloudTrail, pass the raw CloudTrail event JSON (not an envelope).
- You can vendor if desired (`go mod vendor`), but the workspace or `replace` workflow is typically easier.
- For performance, batch process lines and reuse buffers as needed; the mappers expect one event JSON per call.
- Keep `go-ocsf` versions aligned with this repo’s `go.mod` where possible.
- To run unit tests/examples, mirror the patterns under `zeek/tests` JSON files.
- Feel free to alias imports to avoid name collisions between the two `mappers` packages.
- Consider pinning to a specific commit via `replace` for reproducible builds.

