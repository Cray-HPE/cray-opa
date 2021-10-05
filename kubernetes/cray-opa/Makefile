current_dir := $(shell pwd)
tmp_dir := $(shell mktemp -d)

.SILENT: helmlint eval test test-ingressgateway test-ingressgateway-customer-admin test-ingressgateway-customer-user test-ingressgateway-hmn test-ingressgateway-xname-enabled test-ingressgateway-xname-disabled test-ingressgateway-hmn-xname-enabled test-ingressgateway-hmn-xname-disabled 
.PHONY: helmlint eval test test-ingressgateway test-ingressgateway-customer-admin test-ingressgateway-customer-user test-ingressgateway-hmn test-ingressgateway-xname-enabled test-ingressgateway-xname-disabled test-ingressgateway-hmn-xname-enabled test-ingressgateway-hmn-xname-disabled 

all: helmlint eval test test-ingressgateway test-ingressgateway-customer-admin test-ingressgateway-customer-user test-ingressgateway-hmn test-ingressgateway-xname-enabled test-ingressgateway-xname-disabled test-ingressgateway-hmn-xname-enabled test-ingressgateway-hmn-xname-disabled 

lint: helmlint eval 
test-opa: test-ingressgateway test-ingressgateway-customer-admin test-ingressgateway-customer-user test-ingressgateway-hmn test-ingressgateway-xname-enabled test-ingressgateway-xname-disabled test-ingressgateway-hmn-xname-enabled test-ingressgateway-hmn-xname-disabled 

eval:
	helm kubeval

helmlint:
	helm kubeval -n opa cray-opa . --ignore-missing-schemas

cray-opa-test:
	docker build -f tests/opa/Dockerfile --tag cray-opa-test .
	docker build -f tests/opa/xname-enabled/Dockerfile --tag cray-opa-test-xname-enabled .
	docker build -f tests/opa/xname-disabled/Dockerfile --tag cray-opa-test-xname-disabled .

test:
	kubectl kuttl test --kind-config kind.yaml --artifacts-dir /tmp/kuttl

test-ingressgateway:
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway.tpl /mnt/tests/opa/ingressgateway_policy_test.rego.tpl ingressgateway.policy

test-ingressgateway-xname-enabled:
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test-xname-enabled /mnt/templates/_policy-ingressgateway.tpl /mnt/tests/opa/ingressgateway_policy_test.xname_workloads.rego.tpl ingressgateway.policy
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test-xname-enabled /mnt/templates/_policy-ingressgateway.tpl /mnt/tests/opa/ingressgateway_policy_test.xname_workloads.invalid_xname.rego.tpl ingressgateway.policy

test-ingressgateway-xname-disabled:
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test-xname-disabled /mnt/templates/_policy-ingressgateway.tpl /mnt/tests/opa/ingressgateway_policy_test.xname_workloads.rego.tpl ingressgateway.policy

test-ingressgateway-customer-admin:
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway-customer-admin.tpl /mnt/tests/opa/ingressgateway-customer-admin_policy_test.rego.tpl ingressgateway-customer-admin.policy

test-ingressgateway-customer-user:
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway-customer-user.tpl /mnt/tests/opa/ingressgateway-customer-user_policy_test.rego.tpl ingressgateway-customer-user.policy

test-ingressgateway-hmn-xname-enabled:
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test-xname-enabled /mnt/templates/_policy-ingressgateway-hmn.tpl /mnt/tests/opa/ingressgateway_policy_test.xname_workloads.rego.tpl ingressgateway-hmn.policy
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test-xname-enabled /mnt/templates/_policy-ingressgateway-hmn.tpl /mnt/tests/opa/ingressgateway_policy_test.xname_workloads.invalid_xname.rego.tpl ingressgateway-hmn.policy
test-ingressgateway-hmn-xname-disabled:
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test-xname-disabled /mnt/templates/_policy-ingressgateway-hmn.tpl /mnt/tests/opa/ingressgateway_policy_test.xname_workloads.rego.tpl ingressgateway-hmn.policy
