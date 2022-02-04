#
# MIT License
#
# (C) Copyright 2021-2022 Hewlett Packard Enterprise Development LP
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
#
current_dir := $(shell pwd)
tmp_dir := $(shell mktemp -d)

.SILENT: helmlint eval test test-ingressgateway test-ingressgateway-customer-admin test-ingressgateway-xname-enabled test-ingressgateway-xname-disabled 
.PHONY: helmlint eval test test-ingressgateway test-ingressgateway-customer-admin test-ingressgateway-xname-enabled test-ingressgateway-xname-disabled 

all: helmlint eval test test-ingressgateway test-ingressgateway-customer-admin test-ingressgateway-customer-user test-ingressgateway-xname-enabled test-ingressgateway-xname-disabled 

lint: helmlint eval 
test-opa: test-ingressgateway test-ingressgateway-customer-admin test-ingressgateway-customer-user test-ingressgateway-xname-enabled test-ingressgateway-xname-disabled 

eval:
	helm kubeval -n opa cray-opa . --ignore-missing-schemas

helmlint:
	helm lint

cray-opa-test:
	docker build -f tests/opa/Dockerfile --tag cray-opa-test .
	docker build -f tests/opa/xname-enabled/Dockerfile --tag cray-opa-test-xname-enabled .
	docker build -f tests/opa/xname-disabled/Dockerfile --tag cray-opa-test-xname-disabled .

test:
	kubectl kuttl test --kind-config kind.yaml --artifacts-dir /tmp/kuttl

test-ingressgateway:
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway.tpl /mnt/tests/opa/ingressgateway_policy_test.rego.tpl ingressgateway.policy
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway.tpl /mnt/tests/opa/ingressgateway_policy_xforward_test.rego.tpl ingressgateway.policy

test-ingressgateway-xname-enabled:
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test-xname-enabled /mnt/templates/_policy-ingressgateway.tpl /mnt/tests/opa/ingressgateway_policy_test.xname_workloads.rego.tpl ingressgateway.policy
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test-xname-enabled /mnt/templates/_policy-ingressgateway.tpl /mnt/tests/opa/ingressgateway_policy_test.xname_workloads.invalid_xname.rego.tpl ingressgateway.policy

test-ingressgateway-xname-disabled:
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test-xname-disabled /mnt/templates/_policy-ingressgateway.tpl /mnt/tests/opa/ingressgateway_policy_test.xname_workloads.rego.tpl ingressgateway.policy

test-ingressgateway-customer-admin:
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway-customer-admin.tpl /mnt/tests/opa/ingressgateway-customer-admin_policy_test.rego.tpl ingressgateway-customer-admin.policy
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway-customer-admin.tpl /mnt/tests/opa/ingressgateway-customer-admin_policy_xforward_test.rego.tpl ingressgateway-customer-admin.policy

test-ingressgateway-customer-user:
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway-customer-user.tpl /mnt/tests/opa/ingressgateway-customer-user_policy_test.rego.tpl ingressgateway-customer-user.policy
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway-customer-user.tpl /mnt/tests/opa/ingressgateway-customer-user_policy_xforward_test.rego.tpl ingressgateway-customer-user.policy
