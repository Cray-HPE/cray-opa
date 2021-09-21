current_dir := $(shell pwd)
tmp_dir := $(shell mktemp -d)

.SILENT: helmlint eval test unittest test-ingressgateway test-ingressgateway-customer-admin test-ingressgateway-customer-user test-ingressgateway-hmn cray-opa-test
.PHONY: helmlint eval test unittest test-ingressgateway test-ingressgateway-customer-admin test-ingressgateway-customer-user test-ingressgateway-hmn cray-opa-test

all: helmlint eval unittest test test-ingressgateway test-ingressgateway-customer-admin test-ingressgateway-customer-user test-ingressgateway-hmn

lint: helmlint eval unittest
test-opa: test-ingressgateway test-ingressgateway-customer-admin test-ingressgateway-customer-user test-ingressgateway-hmn

eval:
	helm kubeval -n istio-system cray-istio . --ignore-missing-schemas

helmlint:
	helm lint

cray-opa-test:
	docker build -f tests/opa/Dockerfile --tag cray-opa-test .

test:
	kubectl kuttl test --kind-config kind.yaml --artifacts-dir /tmp/kuttl

test-ingressgateway:
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway.tpl /mnt/tests/opa/ingressgateway_policy_test.rego.tpl ingressgateway.policy

test-ingressgateway-customer-admin:
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway-customer-admin.tpl /mnt/tests/opa/ingressgateway-customer-admin_policy_test.rego.tpl ingressgateway-customer-admin.policy

test-ingressgateway-customer-user:
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway-customer-user.tpl /mnt/tests/opa/ingressgateway-customer-user_policy_test.rego.tpl ingressgateway-customer-user.policy

test-ingressgateway-hmn:
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway-hmn.tpl /mnt/tests/opa/ingressgateway-hmn_policy_test.rego.tpl ingressgateway-hmn.policy
