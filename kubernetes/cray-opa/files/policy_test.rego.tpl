# Copyright 2021 Hewlett Packard Enterprise Development LP

package istio.authz

# allow.http_status is 403 when the request is rejected due to the default allow.
# allow.http_status is not present the request is successful because the result is true.

test_allow_bypassed_urls_with_no_auth_header {
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/keycloak"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/vcs"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/repository"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/v2"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/service/rest"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/apis/tokens"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/capsules/"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/spire-jwks-token/"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/spire-jwks-test/"}}}}
}

test_deny_apis_with_no_auth_header {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"path": "/apis/api1"}}}}
}

test_user_when_admin_required {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/api1", "headers": {"authorization": "Bearer {{ .userToken }}"}}}}}
}

test_user {
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/uas-mgr/v1/", "headers": {"authorization": "Bearer {{ .userToken }}"}}}}}
}

test_admin {
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/api1", "headers": {"authorization": "Bearer {{ .adminToken }}"}}}}}
}

# Tests for system-pxe role

pxe_auth = "Bearer {{ .pxeToken }}"

bss_mock_path = "/apis/bss/mock"

test_pxe {

  # BSS - Allowed

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": bss_mock_path, "headers": {"authorization": pxe_auth}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": bss_mock_path, "headers": {"authorization": pxe_auth}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": bss_mock_path, "headers": {"authorization": pxe_auth}}}}}

  # BSS - Not Allowed

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": bss_mock_path, "headers": {"authorization": pxe_auth}}}}}
}

# Tests for system-compute role

compute_auth = "Bearer {{ .computeToken }}"

cfs_mock_path = "/apis/cfs/mock"
cps_mock_path = "/apis/v2/cps/mock"
hbtb_mock_path = "/apis/hbtd/mock"
nmd_mock_path = "/apis/v2/nmd/mock"
smd_mock_path = "/apis/smd/mock"
hmnfd_mock_path = "/apis/hmnfd/mock"
pals_mock_path = "/apis/pals/v1/mock"

test_compute {

  # CFS - Allowed

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": cfs_mock_path, "headers": {"authorization": compute_auth}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cfs_mock_path, "headers": {"authorization": compute_auth}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": cfs_mock_path, "headers": {"authorization": compute_auth}}}}}

  # CFS - Not Allowed

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": cfs_mock_path, "headers": {"authorization": compute_auth}}}}}

  # CPS - Allowed

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": cps_mock_path, "headers": {"authorization": compute_auth}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cps_mock_path, "headers": {"authorization": compute_auth}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": cps_mock_path, "headers": {"authorization": compute_auth}}}}}

  # HBTB - Allowed

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": hbtb_mock_path, "headers": {"authorization": compute_auth}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": hbtb_mock_path, "headers": {"authorization": compute_auth}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": hbtb_mock_path, "headers": {"authorization": compute_auth}}}}}

  # HBTB - Not Allowed

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": hbtb_mock_path, "headers": {"authorization": compute_auth}}}}}

  # NMD - Allowed

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": nmd_mock_path, "headers": {"authorization": compute_auth}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": nmd_mock_path, "headers": {"authorization": compute_auth}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": nmd_mock_path, "headers": {"authorization": compute_auth}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PUT", "path": nmd_mock_path, "headers": {"authorization": compute_auth}}}}}

  # NMD - Not Allowed

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": nmd_mock_path, "headers": {"authorization": compute_auth}}}}}

  # SMD - Allowed

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": smd_mock_path, "headers": {"authorization": compute_auth}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": smd_mock_path, "headers": {"authorization": compute_auth}}}}}

  # SMD - Not Allowed

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": smd_mock_path, "headers": {"authorization": compute_auth}}}}}

  # HMNFD - Allowed

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": hmnfd_mock_path, "headers": {"authorization": compute_auth}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": hmnfd_mock_path, "headers": {"authorization": compute_auth}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": hmnfd_mock_path, "headers": {"authorization": compute_auth}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": hmnfd_mock_path, "headers": {"authorization": compute_auth}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": hmnfd_mock_path, "headers": {"authorization": compute_auth}}}}}

  # HMNFD - Not Allowed

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "TRACE", "path": hmnfd_mock_path, "headers": {"authorization": compute_auth}}}}}
}

# Tests for wlm role
wlm_auth = "Bearer {{ .wlmToken }}"

test_wlm {
  # PALS - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/pals/v1/apps", "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/pals/v1/apps", "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/pals/v1/apps", "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/pals/v1/apps", "headers": {"authorization": wlm_auth}}}}}
  # CAPMC - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/capmc/capmc/v1/set_power_cap", "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/capmc/capmc/v1/set_power_cap", "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/set_power_cap", "headers": {"authorization": wlm_auth}}}}}
  # CAPMC - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/capmc/capmc/v1/set_power_cap", "headers": {"authorization": wlm_auth}}}}}
  # BOS - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/bos/v1/session", "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/bos/v1/session", "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/bos/v1/session", "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": "/apis/bos/v1/session", "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/bos/v1/session", "headers": {"authorization": wlm_auth}}}}}
  # SLS - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/sls/v1/hardware", "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/sls/v1/hardware", "headers": {"authorization": wlm_auth}}}}}
  # SLS - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/sls/v1/hardware", "headers": {"authorization": wlm_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/sls/v1/hardware", "headers": {"authorization": wlm_auth}}}}}
  # SMD - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/smd/hsm/v1/State/Components", "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/smd/hsm/v1/State/Components", "headers": {"authorization": wlm_auth}}}}}
  # SMD - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/smd/hsm/v1/State/Components", "headers": {"authorization": wlm_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/smd/hsm/v1/State/Components", "headers": {"authorization": wlm_auth}}}}}
  # FC - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/fc/v2/port-sets", "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/fc/v2/port-sets", "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/fc/v2/port-sets", "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/fc/v2/port-sets", "headers": {"authorization": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/fc/v2/port-sets", "headers": {"authorization": wlm_auth}}}}}
}

# Tests for unauthorized role for any policy (maps to shasta role 'invalid-role')

unauthorized_role_auth = "Bearer {{ .invalidToken }}"

test_unauth_role {

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": pals_mock_path, "headers": {"authorization": unauthorized_role_auth}}}}}

}

# SPIRE Tests
test_spire_correct_aud {
  correct_aud_token = "Bearer {{ .spireToken }}"

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/cfs/test", "headers": {"authorization": correct_aud_token}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/cfs/test", "headers": {"authorization": correct_aud_token}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": "/apis/cfs/test", "headers": {"authorization": correct_aud_token}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/cps/test", "headers": {"authorization": correct_aud_token}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/v2/cps/test", "headers": {"authorization": correct_aud_token}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/v2/cps/test", "headers": {"authorization": correct_aud_token}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/hbtd/test", "headers": {"authorization": correct_aud_token}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/hbtd/test", "headers": {"authorization": correct_aud_token}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/hbtd/test", "headers": {"authorization": correct_aud_token}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/nmd/test", "headers": {"authorization": correct_aud_token}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/v2/nmd/test", "headers": {"authorization": correct_aud_token}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/v2/nmd/test", "headers": {"authorization": correct_aud_token}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/v2/nmd/test", "headers": {"authorization": correct_aud_token}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/smd/test", "headers": {"authorization": correct_aud_token}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/smd/test", "headers": {"authorization": correct_aud_token}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/hmnfd/test", "headers": {"authorization": correct_aud_token}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/hmnfd/test", "headers": {"authorization": correct_aud_token}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": "/apis/hmnfd/test", "headers": {"authorization": correct_aud_token}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/hmnfd/test", "headers": {"authorization": correct_aud_token}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/hmnfd/test", "headers": {"authorization": correct_aud_token}}}}}

  # Validate that we're not allowing any method with a valid aud through
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/cfs/test", "headers": {"authorization": correct_aud_token}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/v2/cps/test", "headers": {"authorization": correct_aud_token}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/hbtd/test", "headers": {"authorization": correct_aud_token}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/v2/nmd/test", "headers": {"authorization": correct_aud_token}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/smd/test", "headers": {"authorization": correct_aud_token}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/hmnfd/test", "headers": {"authorization": correct_aud_token}}}}}
}

test_spire_incorrect_aud {
  incorrect_aud_token = "Bearer {{ .spireInvalidAudToken }}"

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/cfs/test", "headers": {"authorization": incorrect_aud_token}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/cfs/test", "headers": {"authorization": incorrect_aud_token}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": "/apis/cfs/test", "headers": {"authorization": incorrect_aud_token}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/cps/test", "headers": {"authorization": incorrect_aud_token}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/v2/cps/test", "headers": {"authorization": incorrect_aud_token}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/v2/cps/test", "headers": {"authorization": incorrect_aud_token}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/hbtd/test", "headers": {"authorization": incorrect_aud_token}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/hbtd/test", "headers": {"authorization": incorrect_aud_token}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/hbtd/test", "headers": {"authorization": incorrect_aud_token}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/nmd/test", "headers": {"authorization": incorrect_aud_token}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/v2/nmd/test", "headers": {"authorization": incorrect_aud_token}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/v2/nmd/test", "headers": {"authorization": incorrect_aud_token}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/smd/test", "headers": {"authorization": incorrect_aud_token}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/smd/test", "headers": {"authorization": incorrect_aud_token}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/hmnfd/test", "headers": {"authorization": incorrect_aud_token}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/hmnfd/test", "headers": {"authorization": incorrect_aud_token}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": "/apis/hmnfd/test", "headers": {"authorization": incorrect_aud_token}}}}}
}
