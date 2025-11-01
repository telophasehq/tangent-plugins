### README: Using the Tangent Plugins in your Go project

This repository contains Go mappers that convert various event sources into OCSF v1.5.0 types

They work out of the box with with https://github.com/telophasehq/tangent:

```sh
git clone https://github.com/telophasehq/tangent-plugins
```

Add them to your tangent config
```yaml
plugins:
  zeek_conn:
    module_type: go
    path: tangent-plugins/zeek/conn
    tests:
      - input: tangent-plugins/zeek-ocsf/conn/tests/input.json
        expected: tangent-plugins/zeek-ocsf/conn/tests/expected.json
  cloudtrail:
    module_type: go
    path: tangent-plugins/aws-ocsf/cloudtrail
    tests:
      - input: tangent-plugins/aws-ocsf/cloudtrail/tests/input.json
        expected: tangent-plugins/aws-ocsf/cloudtrail/tests/expected.json
  github:
    module_type: go
    path: tangent-plugins/github-ocsf/github_audit_api_activity
    tests:
      - input: tangent-plugins/aws-ocsf/github_audit_api_activity/tests/input.json
        expected: tangent-plugins/aws-ocsf/github_audit_api_activity/tests/expected.json
```

Then run the tangent server
```sh
tangent run --config tangent.yaml
```
  
