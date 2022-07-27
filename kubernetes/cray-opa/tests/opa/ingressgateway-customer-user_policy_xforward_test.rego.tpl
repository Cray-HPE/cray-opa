# Copyright 2021 Hewlett Packard Enterprise Development LP

package istio.authz
## HOW TO DO UNIT TESTING
# allow.http_status is 403 when the request is rejected due to the default allow.
# allow.http_status is not present the request is successful because the result is true.

test_allow_bypassed_urls_with_no_auth_header {
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/keycloak"}}}}
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
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/api1", "headers": {"x-forwarded-access-token": "{{ .userToken }}"}}}}}
}

test_user {
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/uas-mgr/v1/", "headers": {"x-forwarded-access-token": "{{ .userToken }}"}}}}}
}

test_deny_admin {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/api1", "headers": {"x-forwarded-access-token": "{{ .adminToken }}"}}}}}
}

test_admin_wrong_typ {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/api1", "headers": {"x-forwarded-access-token": "{{ .invalidTypAdminToken }}"}}}}}
}

# Tests for system-pxe role

pxe_auth = "{{ .pxeToken }}"

bss_good_path = "/apis/bss/boot/v1/bootscript"
bss_bad_path = "/apis/bss/boot/v1/anotherpath"

test_deny_pxe {

  # BSS - Denied for customer admin

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": bss_good_path, "headers": {"x-forwarded-access-token": pxe_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": bss_good_path, "headers": {"x-forwarded-access-token": pxe_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": bss_bad_path, "headers": {"x-forwarded-access-token": pxe_auth}}}}}

}

# Tests for system-compute role

compute_auth = "{{ .computeToken }}"

cfs_mock_path = "/apis/components/cfs/mock"
cps_mock_path = "/apis/v2/cps/mock"
hbtb_heartbeat_path = "/apis/hbtd/hmi/v1/heartbeat"
nmd_mock_path = "/apis/v2/nmd/mock"
smd_statecomponents_path = "/apis/smd/hsm/v2/State/Components"
hmnfd_subscribe_path = "/apis/hmnfd/hmi/v1/subscribe"
hmnfd_subscriptions_path = "/apis/hmnfd/hmi/v1/subscriptions"

pals_mock_path = "/apis/pals/v1/mock"

test_deny_compute {

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
wlm_auth = "{{ .wlmToken }}"

test_wlm {
  # CAPMC - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/get_xname_status", "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/xname_reinit", "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/xname_on", "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/xname_off", "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/get_power_cap", "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/get_power_cap_capabilities", "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/set_power_cap", "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  # CAPMC - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/capmc/capmc/v1/set_power_cap", "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  # BOS - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/bos/v1/session", "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/bos/v1/session", "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/bos/v1/session", "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": "/apis/bos/v1/session", "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/bos/v1/session", "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  # SMD - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": smd_statecomponents_path, "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": smd_statecomponents_path, "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  # SMD - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": smd_statecomponents_path, "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": smd_statecomponents_path, "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  # VNID - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/vnid/fabric/vnis", "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/vnid/fabric/vnis", "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/vnid/fabric/vnis", "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/vnid/fabric/vnis", "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  # VNID - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/vnid/fabric/vnis", "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  # jackaloped - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/jackaloped/fabric/nics", "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/jackaloped/fabric/nics", "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/jackaloped/fabric/nics", "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/jackaloped/fabric/nics", "headers": {"x-forwarded-access-token": wlm_auth}}}}}
  # jackaloped - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/jackaloped/fabric/nics", "headers": {"x-forwarded-access-token": wlm_auth}}}}}
}

# Tests for denying access to pals mock path for ckdump sub

unauthorized_role_auth = "{{ .spire.compute.ckdump }}"

test_unauth_role {

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": pals_mock_path, "headers": {"x-forwarded-access-token": unauthorized_role_auth}}}}}

}

# SPIRE Tests

spire_correct_sub(sub) {

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": cfs_mock_path, "headers": {"x-forwarded-access-token": sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cps_mock_path, "headers": {"x-forwarded-access-token": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cps_mock_path, "headers": {"x-forwarded-access-token": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": cps_mock_path, "headers": {"x-forwarded-access-token": sub}}}}}

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
  spire_correct_sub("{{ .spire.ncn.dvs_hmi }}")
  spire_correct_sub("{{ .spire.ncn.dvs_map }}")
  spire_correct_sub("{{ .spire.ncn.orca }}")
  spire_correct_sub("{{ .spire.compute.cfs_state_reporter }}")
  spire_correct_sub("{{ .spire.compute.cpsmount }}")
  spire_correct_sub("{{ .spire.compute.cpsmount_helper }}")
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

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": smd_statecomponents_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": smd_statecomponents_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": hmnfd_subscriptions_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": hmnfd_subscriptions_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": hmnfd_subscriptions_path, "headers": {"x-forwarded-access-token": spire_sub}}}}}
}
