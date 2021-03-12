# Copyright 2021 Hewlett Packard Enterprise Development LP

## TODO: We should be taring up our policies and serving them up using
## OPA's bundles. We should then configure OPA to fetch the bundles.
## However, since we only have one policy and we have a lot of missing
## pieces to accommodate this, it makes sense to just use a config map for now.

Running unit tests: From the cray-opa directory,

```
$ docker build -f files/Dockerfile --tag cray-opa-test .
$ docker run --rm -v `pwd`:/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy.tpl /mnt/files/policy_test.rego.tpl
```

Note: Make sure the image in the Dockerfile matches the actual OPA image used, check the version.
