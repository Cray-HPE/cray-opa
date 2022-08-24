# cray-opa

This chart installs the [OPA Envoy Plugin](https://github.com/open-policy-agent/opa-envoy-plugin)
used to secure API endpoints in CSM.

## Custom OPA Policies

It's possible to set custom OPA policy modules per OPA Gateway. To configure
this, set `.spec.ingresses.[INGRESS GATEWAY].custom` to a list containing the
ConfigMaps that hold the policy modules you wish to apply. Each module needs
to have the package name `istio.authz`. Do not set the configmap data file name
to 'policy.rego' or else it may replace an existing policy. See the examples
directory for policy samples.

## Testing

Tests are run using `make test`.

## Manually run OPA unit tests

To run opa test manually, first build the cray-opa-test containers.

    docker build -f tests/opa/Dockerfile --tag cray-opa-test .

The docker file takes the policy in the yaml file and the test tpl as arguments.
It also has an optional `-x` switch which will enable xname validation.

    docker run --rm -v ${PWD}:/mnt --entrypoint "/app/run_tests" \
    cray-opa-test [-x] policy.yaml test.tpl

### Requirements

Tests use [Docker](docker.io), [kuttl](https://kuttl.dev), and
[kind](https://kind.sigs.k8s.io). You will need each of these applications
installed in order for `make test` to run properly.
