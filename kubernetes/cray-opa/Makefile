#
# MIT License
#
# (C) Copyright 2022 Hewlett Packard Enterprise Development LP
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

HELM_UNITTEST_IMAGE ?= quintush/helm-unittest:3.7.1-0.2.8
current_dir := $(shell pwd)

.SILENT: kuttl_test chart_test rego_test
.PHONY: kuttl_test chart_test rego_test

test: chart_test rego_test kuttl_test

chart_test:
		helm lint
		docker run --rm -v $(current_dir):/apps ${HELM_UNITTEST_IMAGE} -3 .

kuttl_test:
	kubectl kuttl test --kind-config kind.yaml --artifacts-dir /tmp/kuttl

rego_test:
	docker build -f $(current_dir)/tests/opa/Dockerfile --tag cray-opa-test $(current_dir)
	docker run --rm -v $(current_dir)/:/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/policies/hmn.yaml /mnt/tests/opa/hmn_test.rego.tpl
	docker run --rm -v $(current_dir)/:/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/policies/keycloak-admin.yaml /mnt/tests/opa/keycloak-admin_test.rego.tpl
	docker run --rm -v $(current_dir)/:/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/policies/keycloak-user.yaml /mnt/tests/opa/keycloak-user_test.rego.tpl
	docker run --rm -v $(current_dir)/:/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/policies/spire.yaml /mnt/tests/opa/spire_test.rego.tpl
	docker run --rm -v $(current_dir)/:/mnt --entrypoint "/app/run_tests" cray-opa-test -x /mnt/templates/policies/keycloak-system.yaml /mnt/tests/opa/keycloak-system_test.rego.tpl
	docker run --rm -v $(current_dir)/:/mnt --entrypoint "/app/run_tests" cray-opa-test -x /mnt/templates/policies/spire.yaml /mnt/tests/opa/spire_test.rego.tpl
	docker run --rm -v $(current_dir)/:/mnt --entrypoint "/app/run_tests" cray-opa-test -x /mnt/templates/policies/spire.yaml /mnt/tests/opa/spire_xname_test.rego.tpl
