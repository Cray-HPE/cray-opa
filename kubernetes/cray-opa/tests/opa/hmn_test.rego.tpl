# Copyright 2021-2023 Hewlett Packard Enterprise Development LP

package istio.authz
## HOW TO DO UNIT TESTING
# allow.http_status is 403 when the request is rejected due to the default allow.
# allow.http_status is not present the request is successful because the result is true.

# Limit broad access to keycloak.
test_allow_bypassed_urls_with_no_auth_header {
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/keycloak/realms/shasta/protocol/openid-connect/auth"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/keycloak/realms/shasta/protocol/openid-connect/logout"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/keycloak/realms/shasta/protocol/openid-connect/token"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/keycloak/realms/shasta/protocol/openid-connect/userinfo"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/keycloak/realms/shasta/protocol/openid-connect/certs"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"path": "/keycloak/realms/shasta/.well-known/openid-configuration"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/keycloak/resources/foo"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/keycloak/resources/foo"}}}}
}

test_deny_bypassed_urls_with_no_auth_header {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"path": "/keycloak"}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"path": "/vcs"}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"path": "/repository"}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"path": "/v2"}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"path": "/service/rest"}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"path": "/capsules/"}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"path": "/apis/gozerd/"}}}}
}

# Mitigate CVE-2020-10770
test_keycloak_cve_2020_10770 {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"path": "/keycloak/realms/shasta/protocol/openid-connect/auth?scope=openid&response_type=code&redirect_uri=valid&state=cfx&nonce=cfx&client_id=security-admin-console&request_uri=http://hook.url'"}}}}
}

test_deny_tokens_api {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"path": "/apis/tokens"}}}}
}

test_deny_apis__no_auth_header {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"path": "/apis/api1"}}}}
}

test_user_when_admin_required {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/fabric-manager/mock", "headers": {"authorization": "Bearer {{ .userToken }}"}}}}}
}

test_deny_admin_random_api {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/api1", "headers": {"authorization": "Bearer {{ .adminToken }}"}}}}}
}

# Tests for all Slingshot roles

fabric_mock_path = "/apis/fabric-manager/fabric/agents/x0c0r0b0"
certmgr_mock_path = "/apis/fabric-manager/certmgr/switch-certificates/x0c0r0b0"
fabric_rosetta_auth_token_mock_path = "/apis/fabric-manager/fabric/rosetta-auth-token"
fabric_telemetry_mock_path = "/apis/fabric-manager/telemetry/test1"
fabric_switch_telemetry_mock_path = "/apis/fabric-manager/switch-telemetry/test1"
fabric_host_settings_mock_path = "/apis/fabric-manager/host-settings"

test_allow_fabric_when_admin {
  # Deny random api path
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/api/api1", "headers": {"authorization": "Bearer {{ .adminToken }}" }}}}}

  # Allow fabric path
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .adminToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .adminToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .adminToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .adminToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PUT", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .adminToken }}" }}}}}
}

test_allow_fabric_when_system_slingshot {
  # Deny random api path
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/api/api1", "headers": {"authorization": "Bearer {{ .systemSlingshotToken }}" }}}}}

  # Allow Fabric Manager endpoints
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .systemSlingshotToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .systemSlingshotToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .systemSlingshotToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .systemSlingshotToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PUT", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .systemSlingshotToken }}" }}}}}
}

test_allow_fabric_when_slingshot_admin {
  # Deny random api path
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/api/api1", "headers": {"authorization": "Bearer {{ .slingshotAdminToken }}" }}}}}

  # Allow Fabric Manager endpoints
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .slingshotAdminToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .slingshotAdminToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .slingshotAdminToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .slingshotAdminToken }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PUT", "path": fabric_mock_path, "headers": {"authorization": "Bearer {{ .slingshotAdminToken }}" }}}}}
}

test_allow_fabric_when_slingshot_operator {
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

test_allow_fabric_when_slingshot_security {
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

test_allow_fabric_when_slingshot_guest {
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

# Spire is disabled on hms

test_deny_spire_subs {
  spire_correct_sub("Bearer {{ .spire.ncn.cfs_state_reporter }}")
  spire_correct_sub("Bearer {{ .spire.ncn.cpsmount }}")
  spire_correct_sub("Bearer {{ .spire.ncn.cpsmount_helper }}")
  spire_correct_sub("Bearer {{ .spire.ncn.cos_config_helper}}")
  spire_correct_sub("Bearer {{ .spire.ncn.dvs_hmi }}")
  spire_correct_sub("Bearer {{ .spire.ncn.dvs_map }}")
  spire_correct_sub("Bearer {{ .spire.ncn.orca }}")
  spire_correct_sub("Bearer {{ .spire.compute.cfs_state_reporter }}")
  spire_correct_sub("Bearer {{ .spire.compute.cpsmount }}")
  spire_correct_sub("Bearer {{ .spire.compute.cpsmount_helper }}")
  spire_correct_sub("Bearer {{ .spire.compute.cos_config_helper }}")
  spire_correct_sub("Bearer {{ .spire.compute.dvs_hmi }}")
  spire_correct_sub("Bearer {{ .spire.compute.dvs_map }}")
  spire_correct_sub("Bearer {{ .spire.compute.orca }}")
}

spire_ckdump(spire_sub) {

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": nmd_mock_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": nmd_mock_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": nmd_mock_path, "headers": {"authorization": spire_sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cfs_mock_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cfs_mock_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": cfs_mock_path, "headers": {"authorization": spire_sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cps_mock_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cps_mock_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": cps_mock_path, "headers": {"authorization": spire_sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cos_config_mock_path, "headers": {"authorization": spire_sub}}}}}
}

test_deny_spire_ckdump {
  spire_ckdump("Bearer {{ .spire.compute.ckdump }}")
  spire_ckdump("Bearer {{ .spire.ncn.ckdump }}")
  spire_ckdump("Bearer {{ .spire.compute.ckdump_helper }}")
  spire_ckdump("Bearer {{ .spire.ncn.ckdump_helper }}")
}

test_spire_invalid_sub {
  spire_sub = "Bearer {{ .spire.invalidSub }}"

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": nmd_mock_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": nmd_mock_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": nmd_mock_path, "headers": {"authorization": spire_sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cfs_mock_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cfs_mock_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": cfs_mock_path, "headers": {"authorization": spire_sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cps_mock_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cps_mock_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": cps_mock_path, "headers": {"authorization": spire_sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cos_config_mock_path, "headers": {"authorization": spire_sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": smd_statecomponents_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": smd_statecomponents_path, "headers": {"authorization": spire_sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": hmnfd_subscriptions_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": hmnfd_subscriptions_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": hmnfd_subscriptions_path, "headers": {"authorization": spire_sub}}}}}
}
