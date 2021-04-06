## TODO: We should be taring up our policies and serving them up using
## OPA's bundles. We should then configure OPA to fetch the bundles.
## However, since we only have one policy and we have a lot of missing
## pieces to accommodate this, it makes sense to just use a config map for now.

Note that since the switch to using http.send in the Rego and switched the Rego
to a template the unit tests will not run.

Running unit tests: From the files directory,

```
docker run --rm -v `pwd`:/mnt dtr.dev.cray.com:443/openpolicyagent/opa:0.24.0-envoy-1 test /mnt/policy.rego /mnt/policy_test.rego -v
```

Note: Make sure the image matches the actual image used, check the version.
