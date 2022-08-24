# cray-opa

This chart installs the [OPA Envoy Plugin](https://github.com/open-policy-agent/opa-envoy-plugin)
used to secure API endpoints in CSM.

## Custom OPA Policies

It's possible to set custom OPA policy modules per OPA Gateway. This is done by
setting `.spec.ingresses.[INGRESS GATEWAY].custom` to a list containing the
ConfigMaps that hold the policy modules you wish to apply. Each module needs
to have the package name `istio.authz`. Do not set the configmap data file name
to 'policy.rego' or else it may replace an existing policy. See the examples
directory for policy samples.

## Testing

Tests are run via `make test`.

### Requirements

Tests use [Docker](docker.io), [kuttl](https://kuttl.dev), and
[kind](https://kind.sigs.k8s.io). You will need each of these applications
installed in order for `make test` to run properly.
