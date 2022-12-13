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
NAME ?= cray-opa
CHART_PATH ?= kubernetes
CHART_VERSION ?= local

HELM_UNITTEST_IMAGE ?= quintush/helm-unittest:3.3.0-0.2.5

all : test chart
test: chart_test rego_test
chart: chart_setup chart_package

chart_setup:
		mkdir -p ${CHART_PATH}/.packaged

chart_package:
		helm dep up ${CHART_PATH}/${NAME}
		helm package ${CHART_PATH}/${NAME} -d ${CHART_PATH}/.packaged --version ${CHART_VERSION}

chart_test:
		helm lint "${CHART_PATH}/${NAME}"
		docker run --rm -v ${PWD}/${CHART_PATH}:/apps ${HELM_UNITTEST_IMAGE} -3 ${NAME}

rego_test:
	docker build -f ${CHART_PATH}/cray-opa/tests/opa/Dockerfile --tag cray-opa-test ${CHART_PATH}/cray-opa
	docker build -f ${CHART_PATH}/cray-opa/tests/opa/xname-enabled/Dockerfile --tag cray-opa-test-xname-enabled ${CHART_PATH}/cray-opa
	docker build -f ${CHART_PATH}/cray-opa/tests/opa/xname-disabled/Dockerfile --tag cray-opa-test-xname-disabled ${CHART_PATH}/cray-opa
	docker run --rm -v ${PWD}/${CHART_PATH}/cray-opa/:/mnt --entrypoint "/app/run_tests" cray-opa-test-xname-enabled /mnt/templates/_policy-ingressgateway.tpl /mnt/tests/opa/ingressgateway_policy_test.xname_workloads.rego.tpl ingressgateway.policy
	docker run --rm -v ${PWD}/${CHART_PATH}/cray-opa/:/mnt --entrypoint "/app/run_tests" cray-opa-test-xname-enabled /mnt/templates/_policy-ingressgateway.tpl /mnt/tests/opa/ingressgateway_policy_test.xname_workloads.invalid_xname.rego.tpl ingressgateway.policy
	docker run --rm -v ${PWD}/${CHART_PATH}/cray-opa/:/mnt --entrypoint "/app/run_tests" cray-opa-test-xname-disabled /mnt/templates/_policy-ingressgateway.tpl /mnt/tests/opa/ingressgateway_policy_test.xname_workloads.rego.tpl ingressgateway.policy
	docker run --rm -v ${PWD}/${CHART_PATH}/cray-opa/:/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway-customer-admin.tpl /mnt/tests/opa/ingressgateway-customer-admin_policy_test.rego.tpl ingressgateway-customer-admin.policy
	docker run --rm -v ${PWD}/${CHART_PATH}/cray-opa/:/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway-customer-user.tpl /mnt/tests/opa/ingressgateway-customer-user_policy_test.rego.tpl ingressgateway-customer-user.policy
	docker run --rm -v ${PWD}/${CHART_PATH}/cray-opa/:/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway.tpl /mnt/tests/opa/ingressgateway_policy_test.rego.tpl ingressgateway.policy
	docker run --rm -v ${PWD}/${CHART_PATH}/cray-opa/:/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway.tpl /mnt/tests/opa/ingressgateway_policy_xforward_test.rego.tpl ingressgateway.policy
	docker run --rm -v ${PWD}/${CHART_PATH}/cray-opa/:/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway-customer-admin.tpl /mnt/tests/opa/ingressgateway-customer-admin_policy_xforward_test.rego.tpl ingressgateway-customer-admin.policy
	docker run --rm -v ${PWD}/${CHART_PATH}/cray-opa/:/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway-customer-user.tpl /mnt/tests/opa/ingressgateway-customer-user_policy_xforward_test.rego.tpl ingressgateway-customer-user.policy
	docker run --rm -v ${PWD}/${CHART_PATH}/cray-opa/:/mnt --entrypoint "/app/run_tests" cray-opa-test /mnt/templates/_policy-ingressgateway-hmn.tpl /mnt/tests/opa/ingressgateway-hmn_policy_test.rego.tpl ingressgateway-hmn.policy
