current_dir := $(shell pwd)
tmp_dir := $(shell mktemp -d)

.SILENT: helmlint eval test unittest test-ingressgateway test-ingressgateway-customer-admin test-ingressgateway-customer-user test-ingressgateway-hmn cray-opa-test
.PHONY: helmlint eval test unittest test-ingressgateway test-ingressgateway-customer-admin test-ingressgateway-customer-user test-ingressgateway-hmn cray-opa-test

all: helmlint eval unittest test

lint: helmlint eval unittest
test-opa: test-ingressgateway test-ingressgateway-customer-admin test-ingressgateway-customer-user test-ingressgateway-hmn

eval:
	helm template -n opa cray-opa . > $(tmp_dir)/chart.yaml
	docker run -it -v $(tmp_dir):/chart garethr/kubeval:latest --ignore-missing-schemas /chart/chart.yaml

yamllint:
	docker run -it -v $(current_dir):/chart quay.io/helmpack/chart-testing:latest yamllint -c /etc/ct/lintconf.yaml /chart

yamale:
	docker run -it -v $(current_dir):/chart quay.io/helmpack/chart-testing:latest yamale -s /etc/ct/chart_schema.yaml /chart

helmlint:
	helm lint

cray-opa-test:
	docker build -f files/Dockerfile --tag cray-opa-test .

test-ingressgateway:
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway.tpl /mnt/tests/opa/ingressgateway_policy_test.rego.tpl ingressgateway.policy

test-ingressgateway-customer-admin:
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway-customer-admin.tpl /mnt/tests/opa/ingressgateway-customer-admin_policy_test.rego.tpl ingressgateway-customer-admin.policy

test-ingressgateway-customer-user:
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway-customer-user.tpl /mnt/tests/opa/ingressgateway-customer-user_policy_test.rego.tpl ingressgateway-customer-user.policy

test-ingressgateway-hmn:
	docker run --rm -v $(current_dir):/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway-hmn.tpl /mnt/tests/opa/ingressgateway-hmn_policy_test.rego.tpl ingressgateway-hmn.policy
