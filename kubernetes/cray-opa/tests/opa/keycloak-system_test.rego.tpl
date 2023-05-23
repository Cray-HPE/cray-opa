# Copyright 2021-2023 Hewlett Packard Enterprise Development LP

package istio.authz
## HOW TO DO UNIT TESTING
# allow.http_status is 403 when the request is rejected due to the default allow.
# allow.http_status is not present the request is successful because the result is true.

test_allow_bypassed_urls_with_no_auth_header {
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/keycloak", "host": "auth.cmn.acme.com"}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"path": "/keycloak", "host": "auth.nmnlb.acme.com"}}}}
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
}

test_user_when_admin_required {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/api1", "headers": {"authorization": "Bearer {{ .userToken }}"}}}}}
}

# Mitigate CVE-2020-10770
test_keycloak_cve_2020_10770 {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"path": "/keycloak/realms/shasta/protocol/openid-connect/auth?scope=openid&response_type=code&redirect_uri=valid&state=cfx&nonce=cfx&client_id=security-admin-console&request_uri=http://hook.url'"}}}}
}

# Tests for system-pxe role

pxe_auth = "Bearer {{ .pxeToken }}"

bss_good_path = "/apis/bss/boot/v1/bootscript"
bss_bad_path = "/apis/bss/boot/v1/anotherpath"

test_pxe {

  # BSS - Allowed

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": bss_good_path, "headers": {"authorization": pxe_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": bss_good_path, "headers": {"authorization": pxe_auth}}}}}

  # BSS - Not Allowed

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": bss_bad_path, "headers": {"authorization": pxe_auth}}}}}

}

# Tests for system-compute role

compute_auth = "Bearer {{ .computeToken }}"

cfs_mock_path = "/apis/cfs/components/mock"
hbtb_heartbeat_path = "/apis/hbtd/hmi/v1/heartbeat"
nmd_mock_path = "/apis/v2/nmd/mock"
smd_statecomponents_path = "/apis/smd/hsm/v2/State/Components"
hmnfd_subscribe_path = "/apis/hmnfd/hmi/v1/subscribe"
hmnfd_subscriptions_path = "/apis/hmnfd/hmi/v1/subscriptions"

pals_mock_path = "/apis/pals/v1/mock"

test_compute {

  # CFS - Allowed

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": cfs_mock_path, "headers": {"authorization": compute_auth}}}}}

  # CFS - Not Allowed

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cfs_mock_path, "headers": {"authorization": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cfs_mock_path, "headers": {"authorization": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": cfs_mock_path, "headers": {"authorization": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": cfs_mock_path, "headers": {"authorization": compute_auth}}}}}

  # CPS - Allowed

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/cps/transports", "headers": {"authorization": compute_auth}}}}}


  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/v2/cps/transports", "headers": {"authorization": compute_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/v2/cps/contents", "headers": {"authorization": compute_auth}}}}}

  # NMD - Allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/cos/configs", "headers": {"authorization": compute_auth}}}}}

  # NMD - Allowed

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/v2/nmd/status/x1", "headers": {"authorization": compute_auth}}}}}

  # NMD - Not Allowed

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": nmd_mock_path, "headers": {"authorization": compute_auth}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": nmd_mock_path, "headers": {"authorization": compute_auth}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": nmd_mock_path, "headers": {"authorization": compute_auth}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": nmd_mock_path, "headers": {"authorization": compute_auth}}}}}

  # SMD - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": smd_statecomponents_path, "headers": {"authorization": compute_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": smd_statecomponents_path, "headers": {"authorization": compute_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": "/apis/smd/hsm/v1/State/Components/BulkSoftwareStatus", "headers": {"authorization": compute_auth}}}}}

  # SMD - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": smd_statecomponents_path, "headers": {"authorization": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": smd_statecomponents_path, "headers": {"authorization": compute_auth}}}}}

  # PCS - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/power-control/v1/power-status?xname=TEST", "headers": {"authorization": compute_auth}}}}}

  # PCS - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/power-control/v1/transitions", "headers": {"authorization": compute_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/power-control/v1/transitions", "headers": {"authorization": compute_auth}}}}}

  # HMNFD - Allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": hmnfd_subscriptions_path, "headers": {"authorization": compute_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": hmnfd_subscriptions_path, "headers": {"authorization": compute_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": hmnfd_subscribe_path, "headers": {"authorization": compute_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": hmnfd_subscribe_path, "headers": {"authorization": compute_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": hmnfd_subscribe_path, "headers": {"authorization": compute_auth}}}}}
  # HMNFD - Not Allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "TRACE", "path": hmnfd_subscribe_path, "headers": {"authorization": compute_auth}}}}}

  # HBTD - Allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": hbtb_heartbeat_path, "headers": {"authorization": compute_auth}}}}}

}
