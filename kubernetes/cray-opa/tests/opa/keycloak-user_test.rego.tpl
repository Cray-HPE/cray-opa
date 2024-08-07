# -*- mode: rego -*-
# Copyright 2021-2023 Hewlett Packard Enterprise Development LP

package istio.authz
## HOW TO DO UNIT TESTING
# allow.http_status is 403 when the request is rejected due to the default allow.
# allow.http_status is not present the request is successful because the result is true.

# Limit broad /keycloak access to requests using the CMN LB
test_allow_bypassed_urls_with_no_auth_header {
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/keycloak/realms/shasta/protocol/openid-connect/auth"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/keycloak/realms/shasta/protocol/openid-connect/logout"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/keycloak/realms/shasta/protocol/openid-connect/token"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/keycloak/realms/shasta/protocol/openid-connect/userinfo"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/keycloak/realms/shasta/protocol/openid-connect/certs"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/keycloak/realms/shasta/.well-known/openid-configuration"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/keycloak/resources/foo"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/keycloak/resources/foo"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/vcs"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/repository"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/v2"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/service/rest"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/capsules/"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/apis/gozerd/"}}}}
}

test_deny_tokens_api {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"path": "/apis/tokens"}}}}
}

test_deny_apis_with_no_auth_header {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"path": "/apis/api1"}}}}
}

test_user_when_admin_required {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/api1", "headers": {"authorization": "Bearer {{ .userToken }}"}}}}}
}

# Mitigate CVE-2020-10770
test_keycloak_cve_2020_10770 {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"path": "/keycloak/realms/shasta/protocol/openid-connect/auth?scope=openid&response_type=code&redirect_uri=valid&state=cfx&nonce=cfx&client_id=security-admin-console&request_uri=http://hook.url'"}}}}
}

test_user {
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/uas-mgr/v1/", "headers": {"authorization": "Bearer {{ .userToken }}"}}}}}
}

test_deny_admin {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/api1", "headers": {"authorization": "Bearer {{ .adminToken }}"}}}}}
}

test_nexus {
  # Allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "nexus_mock_path", "headers": {"x-envoy-decorator-operation": "nexus.nexus.svc.cluster.local:80/*"}}}}}

  # Not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "nexus_mock_path", "headers": {"x-envoy-decorator-operation": "invalid"}}}}}
}

test_grafana {
  # Allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "grafana_mock_path", "headers": {"x-envoy-decorator-operation": "cray-sysmgmt-health-grafana.sysmgmt-health.svc.cluster.local:80/*"}}}}}
}

test_sma_grafana {
  # Allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "sma_grafana_mock_path", "headers": {"x-envoy-decorator-operation": "sma-grafana.services.svc.cluster.local:3000/*"}}}}}
}

test_sma_kibana {
  # Allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "sma_kibana_mock_path", "headers": {"x-envoy-decorator-operation": "sma-kibana.services.svc.cluster.local:5601/*"}}}}}
}

# Tests for system-pxe role

pxe_auth = "Bearer {{ .pxeToken }}"

bss_good_path = "/apis/bss/boot/v1/bootscript"
bss_bad_path = "/apis/bss/boot/v1/anotherpath"

test_deny_pxe {

  # BSS - Denied for customer admin

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": bss_good_path, "headers": {"authorization": pxe_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": bss_good_path, "headers": {"authorization": pxe_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": bss_bad_path, "headers": {"authorization": pxe_auth}}}}}

}

# Tests for system-compute role

compute_auth = "Bearer {{ .computeToken }}"

cfs_mock_path = "/apis/components/cfs/mock"
cps_mock_path = "/apis/v2/cps/mock"
cos_config_mock_path = "/apis/v2/cos/mock"
hbtb_heartbeat_path = "/apis/hbtd/hmi/v1/heartbeat"
nmd_mock_path = "/apis/v2/nmd/mock"
smd_statecomponents_path = "/apis/smd/hsm/v2/State/Components"
hmnfd_subscribe_path = "/apis/hmnfd/hmi/v1/subscribe"
hmnfd_subscriptions_path = "/apis/hmnfd/hmi/v1/subscriptions"

pals_mock_path = "/apis/pals/v1/mock"

test_deny_compute {

  # CFS - Not allowed

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": cfs_mock_path, "headers": {"authorization": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cfs_mock_path, "headers": {"authorization": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cfs_mock_path, "headers": {"authorization": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": cfs_mock_path, "headers": {"authorization": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": cfs_mock_path, "headers": {"authorization": compute_auth}}}}}

  # CFS - Not Allowed

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": cfs_mock_path, "headers": {"authorization": compute_auth}}}}}

  # CPS - Not Allowed

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cps_mock_path, "headers": {"authorization": compute_auth}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cps_mock_path, "headers": {"authorization": compute_auth}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": cps_mock_path, "headers": {"authorization": compute_auth}}}}}

  # COS config - Not Allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cos_config_mock_path, "headers": {"authorization": compute_auth}}}}}

  # NMD - Not Allowed

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": nmd_mock_path, "headers": {"authorization": compute_auth}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": nmd_mock_path, "headers": {"authorization": compute_auth}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": nmd_mock_path, "headers": {"authorization": compute_auth}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": nmd_mock_path, "headers": {"authorization": compute_auth}}}}}


  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": nmd_mock_path, "headers": {"authorization": compute_auth}}}}}

  # SMD - Not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": smd_statecomponents_path, "headers": {"authorization": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": smd_statecomponents_path, "headers": {"authorization": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": "/apis/smd/hsm/v2/State/Components/x1/SoftwareStatus", "headers": {"authorization": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": smd_statecomponents_path, "headers": {"authorization": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": smd_statecomponents_path, "headers": {"authorization": compute_auth}}}}}

  # HMNFD - Not Allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": hmnfd_subscriptions_path, "headers": {"authorization": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": hmnfd_subscriptions_path, "headers": {"authorization": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": hmnfd_subscribe_path, "headers": {"authorization": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": hmnfd_subscribe_path, "headers": {"authorization": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": hmnfd_subscribe_path, "headers": {"authorization": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "TRACE", "path": hmnfd_subscribe_path, "headers": {"authorization": compute_auth}}}}}

  # HBTD - Not Allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": hbtb_heartbeat_path, "headers": {"authorization": compute_auth}}}}}

}

# Tests for wlm role
wlm_auth = "Bearer {{ .wlmToken }}"

test_wlm {
  # CAPMC - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/get_xname_status", "headers": {"authorization": wlm_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/xname_reinit", "headers": {"authorization": wlm_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/xname_on", "headers": {"authorization": wlm_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/xname_off", "headers": {"authorization": wlm_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/get_power_cap", "headers": {"authorization": wlm_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/get_power_cap_capabilities", "headers": {"authorization": wlm_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/set_power_cap", "headers": {"authorization": wlm_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/capmc/capmc/v1/set_power_cap", "headers": {"authorization": wlm_auth}}}}}
  # PCS - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/power-control/v1/power-status?xname=test", "headers": {"authorization": wlm_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/power-control/v1/transitions", "headers": {"authorization": wlm_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": "/apis/power-control/v1/power-cap", "headers": {"authorization": wlm_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/power-control/v1/transitions/test", "headers": {"authorization": wlm_auth}}}}}
  # BOS - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/bos/v2/applystaged", "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/bos/v2/sessions/test", "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/bos/v2/sessions", "headers": {"authorization": wlm_auth}}}}}
  # BOS - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/bos/v1/session", "headers": {"authorization": wlm_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/bos/v1/session", "headers": {"authorization": wlm_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/bos/v1/session", "headers": {"authorization": wlm_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": "/apis/bos/v1/session", "headers": {"authorization": wlm_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/bos/v1/session", "headers": {"authorization": wlm_auth}}}}}
  # SMD - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": smd_statecomponents_path, "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": smd_statecomponents_path, "headers": {"authorization": wlm_auth}}}}}
  # SMD - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": smd_statecomponents_path, "headers": {"authorization": wlm_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": smd_statecomponents_path, "headers": {"authorization": wlm_auth}}}}}
  # VNID - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/vnid/fabric/vnis", "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/vnid/fabric/vnis", "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/vnid/fabric/vnis", "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/vnid/fabric/vnis", "headers": {"authorization": wlm_auth}}}}}
  # VNID - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/vnid/fabric/vnis", "headers": {"authorization": wlm_auth}}}}}
  # jackaloped - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/jackaloped/fabric/nics", "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/jackaloped/fabric/nics", "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/jackaloped/fabric/nics", "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/jackaloped/fabric/nics", "headers": {"authorization": wlm_auth}}}}}
  # jackaloped - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/jackaloped/fabric/nics", "headers": {"authorization": wlm_auth}}}}}
}

test_wlm_xforwarded {
  # CAPMC - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/get_xname_status", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/xname_reinit", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/xname_on", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/xname_off", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/get_power_cap", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/get_power_cap_capabilities", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/set_power_cap", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/capmc/capmc/v1/set_power_cap", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  # PCS - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/power-control/v1/power-status?xname=test", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/power-control/v1/transitions", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": "/apis/power-control/v1/power-cap", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/power-control/v1/transitions/test", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  # BOS - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/bos/v2/applystaged", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/bos/v2/sessions/test", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/bos/v2/sessions", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  # BOS - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/bos/v1/session", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/bos/v1/session", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/bos/v1/session", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": "/apis/bos/v1/session", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/bos/v1/session", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  # SMD - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": smd_statecomponents_path, "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": smd_statecomponents_path, "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  # SMD - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": smd_statecomponents_path, "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": smd_statecomponents_path, "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  # VNID - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/vnid/fabric/vnis", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/vnid/fabric/vnis", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/vnid/fabric/vnis", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/vnid/fabric/vnis", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  # VNID - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/vnid/fabric/vnis", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  # jackaloped - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/jackaloped/fabric/nics", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/jackaloped/fabric/nics", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/jackaloped/fabric/nics", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/jackaloped/fabric/nics", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
  # jackaloped - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/jackaloped/fabric/nics", "headers": {"x-forwarded-access-token": "{{ .wlmToken }}" }}}}}
}
# Tests for denying access to pals mock path for ckdump sub

unauthorized_role_auth = "Bearer {{ .spire.compute.ckdump }}"

test_unauth_role {

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": pals_mock_path, "headers": {"authorization": unauthorized_role_auth}}}}}

}

# SPIRE Tests

spire_correct_sub(sub) {

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": cfs_mock_path, "headers": {"authorization": sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cps_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cps_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": cps_mock_path, "headers": {"authorization": sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cos_config_mock_path, "headers": {"authorization": sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": nmd_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": nmd_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": nmd_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": nmd_mock_path, "headers": {"authorization": sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": smd_statecomponents_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": smd_statecomponents_path, "headers": {"authorization": sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": hmnfd_subscriptions_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": hmnfd_subscriptions_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": hmnfd_subscribe_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": hmnfd_subscribe_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": hmnfd_subscribe_path, "headers": {"authorization": sub}}}}}

  # Validate that we're not allowing any method with a valid aud through
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": cfs_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": cfs_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": cfs_mock_path, "headers": {"authorization": sub}}}}}
}



test_user_when_admin_required_xforwarded {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/api1", "headers": {"x-forwarded-access-token": "{{ .userToken }}"}}}}}
}

test_user_xfowarded {
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/uas-mgr/v1/", "headers": {"x-forwarded-access-token": "{{ .userToken }}"}}}}}
}

test_deny_admin_xfowarded {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/api1", "headers": {"x-forwarded-access-token": "{{ .adminToken }}"}}}}}
}

test_admin_wrong_typ_xfowarded {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/api1", "headers": {"x-forwarded-access-token": "{{ .invalidTypAdminToken }}"}}}}}
}

test_deny_pxe_xforwarded {

  # BSS - Denied for customer admin

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": bss_good_path, "headers": {"x-forwarded-access-token": pxe_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": bss_good_path, "headers": {"x-forwarded-access-token": pxe_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": bss_bad_path, "headers": {"x-forwarded-access-token": pxe_auth}}}}}

}

# Tests for system-compute role

test_deny_compute_xforwarded {

  # CFS - Not allowed

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": cfs_mock_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cfs_mock_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cfs_mock_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": cfs_mock_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": cfs_mock_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}

  # CFS - Not Allowed

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": cfs_mock_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}

  # CPS - Not Allowed

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cps_mock_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cps_mock_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": cps_mock_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}

  # COS config - Not Allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cos_config_mock_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}

  # NMD - Not Allowed

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": nmd_mock_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": nmd_mock_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": nmd_mock_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": nmd_mock_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}


  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": nmd_mock_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}

  # SMD - Not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": smd_statecomponents_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": smd_statecomponents_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": "/apis/smd/hsm/v2/State/Components/x1/SoftwareStatus", "headers": {"x-forwarded-access-token": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": smd_statecomponents_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": smd_statecomponents_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}

  # HMNFD - Not Allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": hmnfd_subscriptions_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": hmnfd_subscriptions_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": hmnfd_subscribe_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": hmnfd_subscribe_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": hmnfd_subscribe_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "TRACE", "path": hmnfd_subscribe_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}

  # HBTD - Not Allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": hbtb_heartbeat_path, "headers": {"x-forwarded-access-token": compute_auth}}}}}

}

# Tests for wlm role

# Tests for denying access to pals mock path for ckdump sub

test_unauth_role_xforwarded {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": pals_mock_path, "headers": {"x-forwarded-access-token": unauthorized_role_auth}}}}}
}

# SPIRE Tests

spire_correct_sub(sub) {

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": cfs_mock_path, "headers": {"x-forwarded-access-token": sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cps_mock_path, "headers": {"x-forwarded-access-token": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cps_mock_path, "headers": {"x-forwarded-access-token": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": cps_mock_path, "headers": {"x-forwarded-access-token": sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cos_config_mock_path, "headers": {"x-forwarded-access-token": sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": nmd_mock_path, "headers": {"x-forwarded-access-token": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": nmd_mock_path, "headers": {"x-forwarded-access-token": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": nmd_mock_path, "headers": {"x-forwarded-access-token": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": nmd_mock_path, "headers": {"x-forwarded-access-token": sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": smd_statecomponents_path, "headers": {"x-forwarded-access-token": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": smd_statecomponents_path, "headers": {"x-forwarded-access-token": sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": hmnfd_subscriptions_path, "headers": {"x-forwarded-access-token": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": hmnfd_subscriptions_path, "headers": {"x-forwarded-access-token": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": hmnfd_subscribe_path, "headers": {"x-forwarded-access-token": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": hmnfd_subscribe_path, "headers": {"x-forwarded-access-token": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": hmnfd_subscribe_path, "headers": {"x-forwarded-access-token": sub}}}}}

  # Validate that we're not allowing any method with a valid aud through
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": cfs_mock_path, "headers": {"x-forwarded-access-token": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": cfs_mock_path, "headers": {"x-forwarded-access-token": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": cfs_mock_path, "headers": {"x-forwarded-access-token": sub}}}}}
}

# Spire is disabled on customer admin

test_deny_spire_subs {
  spire_correct_sub("{{ .spire.ncn.cfs_state_reporter }}")
  spire_correct_sub("{{ .spire.ncn.cpsmount }}")
  spire_correct_sub("{{ .spire.ncn.cpsmount_helper }}")
  spire_correct_sub("{{ .spire.ncn.cos_config_helper }}")
  spire_correct_sub("{{ .spire.ncn.dvs_hmi }}")
  spire_correct_sub("{{ .spire.ncn.dvs_map }}")
  spire_correct_sub("{{ .spire.ncn.orca }}")
  spire_correct_sub("{{ .spire.compute.cfs_state_reporter }}")
  spire_correct_sub("{{ .spire.compute.cpsmount }}")
  spire_correct_sub("{{ .spire.compute.cpsmount_helper }}")
  spire_correct_sub("{{ .spire.compute.cos_config_helper }}")
  spire_correct_sub("{{ .spire.compute.dvs_hmi }}")
  spire_correct_sub("{{ .spire.compute.dvs_map }}")
  spire_correct_sub("{{ .spire.compute.orca }}")
}

spire_ckdump(spire_sub) {

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": nmd_mock_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": nmd_mock_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": nmd_mock_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cfs_mock_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cfs_mock_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": cfs_mock_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cps_mock_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cps_mock_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": cps_mock_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cos_config_mock_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}
}

test_deny_spire_ckdump {
  spire_ckdump("{{ .spire.compute.ckdump }}")
  spire_ckdump("{{ .spire.ncn.ckdump }}")
  spire_ckdump("{{ .spire.compute.ckdump_helper }}")
  spire_ckdump("{{ .spire.ncn.ckdump_helper }}")
}

test_spire_invalid_sub {
  spire_sub = "{{ .spire.invalidSub }}"

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": nmd_mock_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": nmd_mock_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": nmd_mock_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cfs_mock_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cfs_mock_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": cfs_mock_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cps_mock_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cps_mock_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": cps_mock_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cos_config_mock_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": smd_statecomponents_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": smd_statecomponents_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": hmnfd_subscriptions_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": hmnfd_subscriptions_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": hmnfd_subscriptions_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}
}

# Test for all Slingshot roles

fabric_mock_path = "/apis/fabric-manager/fabric/agents/x0c0r0b0"
certmgr_mock_path = "/apis/fabric-manager/certmgr/switch-certificates/x0c0r0b0"
fabric_rosetta_auth_token_mock_path = "/apis/fabric-manager/fabric/rosetta-auth-token"
fabric_telemetry_mock_path = "/apis/fabric-manager/telemetry/test1"
fabric_switch_telemetry_mock_path = "/apis/fabric-manager/switch-telemetry/test1"
fabric_host_settings_mock_path = "/apis/fabric-manager/host-settings"
fabric_collectives_jobs_mock_path = "/apis/fabric-manager/fabric/collectives/jobs/1"
fabric_collectives_multicasts_mock_path = "/apis/fabric-manager/fabric/collectives/multicasts/1"

test_slingshot_when_slingshot_admin {
  # Deny random api path
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/api/api1", "headers": {"authorization": "Bearer {{ .slingshotAdminToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .slingshotAdminToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .slingshotAdminToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .slingshotAdminToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .slingshotAdminToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .slingshotAdminToken }}" }}}}}
}

test_slingshot_when_slingshot_operator {
  # Deny random api path
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/api/api1", "headers": {"authorization": "Bearer {{ .slingshotOperatorToken }}" }}}}}
  # Deny disallowed methods
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .slingshotOperatorToken }}" }}}}}
  # Deny disallowed certmgr path
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": certmgr_mock_path, "headers": {"authorization": "Bearer {{ .slingshotOperatorToken }}" }}}}}

  # Allow Fabric Manager endpoints
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .slingshotOperatorToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .slingshotOperatorToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .slingshotOperatorToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PUT", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .slingshotOperatorToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": fabric_telemetry_mock_path, "headers": {"authorization": "Bearer {{ .slingshotOperatorToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": fabric_telemetry_mock_path, "headers": {"authorization": "Bearer {{ .slingshotOperatorToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": fabric_telemetry_mock_path, "headers": {"authorization": "Bearer {{ .slingshotOperatorToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PUT", "path": fabric_telemetry_mock_path, "headers": {"authorization": "Bearer {{ .slingshotOperatorToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": fabric_switch_telemetry_mock_path, "headers": {"authorization": "Bearer {{ .slingshotOperatorToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": fabric_switch_telemetry_mock_path, "headers": {"authorization": "Bearer {{ .slingshotOperatorToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": fabric_switch_telemetry_mock_path, "headers": {"authorization": "Bearer {{ .slingshotOperatorToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PUT", "path": fabric_switch_telemetry_mock_path, "headers": {"authorization": "Bearer {{ .slingshotOperatorToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": fabric_host_settings_mock_path, "headers": {"authorization": "Bearer {{ .slingshotOperatorToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": fabric_host_settings_mock_path, "headers": {"authorization": "Bearer {{ .slingshotOperatorToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": fabric_host_settings_mock_path, "headers": {"authorization": "Bearer {{ .slingshotOperatorToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PUT", "path": fabric_host_settings_mock_path, "headers": {"authorization": "Bearer {{ .slingshotOperatorToken }}" }}}}}
}

test_slingshot_when_slingshot_security {
  # Deny random api path
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/api/api1", "headers": {"authorization": "Bearer {{ .slingshotSecurityToken }}" }}}}}
  # Deny disallowed Fabric Manager endpoints
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .slingshotSecurityToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .singshotSecurityToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .slingshotSecurityToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .slingshotSecurityToken }}" }}}}}


  # Allow Fabric and Certificate Manager endpoints
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": certmgr_mock_path, "headers": {"authorization": "Bearer {{ .slingshotSecurityToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": certmgr_mock_path, "headers": {"authorization": "Bearer {{ .slingshotSecurityToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": certmgr_mock_path, "headers": {"authorization": "Bearer {{ .slingshotSecurityToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": certmgr_mock_path, "headers": {"authorization": "Bearer {{ .slingshotSecurityToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PUT", "path": certmgr_mock_path, "headers": {"authorization": "Bearer {{ .slingshotSecurityToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": fabric_rosetta_auth_token_mock_path, "headers": {"authorization": "Bearer {{ .slingshotSecurityToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": fabric_rosetta_auth_token_mock_path, "headers": {"authorization": "Bearer {{ .slingshotSecurityToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": fabric_rosetta_auth_token_mock_path, "headers": {"authorization": "Bearer {{ .slingshotSecurityToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PUT", "path": fabric_rosetta_auth_token_mock_path, "headers": {"authorization": "Bearer {{ .slingshotSecurityToken }}" }}}}}
}

test_slingshot_when_slingshot_guest {
  # Deny random api path
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/api/api1", "headers": {"authorization": "Bearer {{ .slingshotGuestToken }}" }}}}}
  # Deny disallowed methods
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .slingshotGuestToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .singshotGuestToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .slingshotGuestToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .slingshotGuestToken }}" }}}}}

  # Allow fabric path
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .slingshotGuestToken }}" }}}}}
}

test_slingshot_when_wlm {
  # Deny disallowed methods
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .wlmToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .singshotGuestToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .wlmToken }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .wlmToken }}" }}}}}

  # Allow fabric path
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .wlmToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": fabric_collectives_jobs_mock_path, "headers": {"authorization": "Bearer {{ .wlmToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": fabric_collectives_jobs_mock_path, "headers": {"authorization": "Bearer {{ .wlmToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": fabric_collectives_jobs_mock_path, "headers": {"authorization": "Bearer {{ .wlmToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PUT", "path": fabric_collectives_jobs_mock_path, "headers": {"authorization": "Bearer {{ .wlmToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": fabric_collectives_multicasts_mock_path, "headers": {"authorization": "Bearer {{ .wlmToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": fabric_collectives_multicasts_mock_path, "headers": {"authorization": "Bearer {{ .wlmToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": fabric_collectives_multicasts_mock_path, "headers": {"authorization": "Bearer {{ .wlmToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PUT", "path": fabric_collectives_multicasts_mock_path, "headers": {"authorization": "Bearer {{ .wlmToken }}" }}}}}
}
