# Copyright 2021-2023 Hewlett Packard Enterprise Development LP

package istio.authz
## HOW TO DO UNIT TESTING
# allow.http_status is 403 when the request is rejected due to the default allow.
# allow.http_status is not present the request is successful because the result is true.

# Limit broad /keycloak access to requests using the CMN LB
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

# Mitigate CVE-2020-10770
test_keycloak_cve_2020_10770 {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"path": "/keycloak/realms/shasta/protocol/openid-connect/auth?scope=openid&response_type=code&redirect_uri=valid&state=cfx&nonce=cfx&client_id=security-admin-console&request_uri=http://hook.url'"}}}}
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

test_user {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/uas-mgr/v1/", "headers": {"authorization": "Bearer {{ .userToken }}"}}}}}
}

test_admin {
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/api1", "headers": {"authorization": "Bearer {{ .adminToken }}"}}}}}
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

cfs_mock_path = "/apis/cfs/components/mock"
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

  # COS config - Not allowed
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

# Tests for denying access to pals mock path for ckdump sub

unauthorized_role_auth = "Bearer {{ .spire.compute.ckdump }}"

test_unauth_role {

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": pals_mock_path, "headers": {"authorization": unauthorized_role_auth}}}}}

}

# Multi Tenancy Tests

test_tenant_admin {

  # Verify infrastructure administrator has access to all endpoints, tenant header or not
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/bos/v2", "headers": {"authorization": "Bearer {{ .adminToken }}"}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/bos/v2", "headers": {"authorization": "Bearer {{ .adminToken }}", "cray-tenant-name": "vcluster-blue"}}}}}

  # Verify infrastructure administrator cannot supply an invalid tenant name
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/bos/v2", "headers": {"authorization": "Bearer {{ .adminToken }}", "cray-tenant-name": ""}}}}}

  # Verify tenant administrator (only authorized for vcluster-blue) can access valid endpoints
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/bos/v2", "headers": {"authorization": "Bearer {{ .tenantAdminToken }}", "cray-tenant-name": "vcluster-blue"}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/bos/v2/applystaged", "headers": {"authorization": "Bearer {{ .tenantAdminToken }}", "cray-tenant-name": "vcluster-blue"}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/bos/v2/components", "headers": {"authorization": "Bearer {{ .tenantAdminToken }}", "cray-tenant-name": "vcluster-blue"}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/bos/v2/components/foo", "headers": {"authorization": "Bearer {{ .tenantAdminToken }}", "cray-tenant-name": "vcluster-blue"}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/bos/v2/healthz", "headers": {"authorization": "Bearer {{ .tenantAdminToken }}", "cray-tenant-name": "vcluster-blue"}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/bos/v2/sessions", "headers": {"authorization": "Bearer {{ .tenantAdminToken }}", "cray-tenant-name": "vcluster-blue"}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/bos/v2/sessions/foo", "headers": {"authorization": "Bearer {{ .tenantAdminToken }}", "cray-tenant-name": "vcluster-blue"}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/bos/v2/sessions/foo/status", "headers": {"authorization": "Bearer {{ .tenantAdminToken }}", "cray-tenant-name": "vcluster-blue"}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/bos/v2/sessiontemplates", "headers": {"authorization": "Bearer {{ .tenantAdminToken }}", "cray-tenant-name": "vcluster-blue"}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/bos/v2/sessiontemplates/foo", "headers": {"authorization": "Bearer {{ .tenantAdminToken }}", "cray-tenant-name": "vcluster-blue"}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/bos/v2/sessions", "headers": {"authorization": "Bearer {{ .tenantAdminToken }}", "cray-tenant-name": "vcluster-blue"}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/bos/v2/version", "headers": {"authorization": "Bearer {{ .tenantAdminToken }}", "cray-tenant-name": "vcluster-blue"}}}}}

  # Verify tenant administrator cannot access unauthorized endpoints
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/api1", "headers": {"authorization": "Bearer {{ .tenantAdminToken }}", "cray-tenant-name": "vcluster-blue"}}}}}

  # Verify tenant administrator cannot access a non-permitted tenant (vcluster-red)
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/bos/v2", "headers": {"authorization": "Bearer {{ .tenantAdminToken }}", "cray-tenant-name": "vcluster-red"}}}}}

  # Verify tenant administrator must supply a tenant header and cannot supply an invalid tenant name
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/bos/v2", "headers": {"authorization": "Bearer {{ .tenantAdminToken }}"}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/bos/v2", "headers": {"authorization": "Bearer {{ .tenantAdminToken }}", "cray-tenant-name": ""}}}}}
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

# Tests with x-forwarded-access-token

test_deny_pxe_xforwarded {

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": bss_good_path, "headers": {"x-forwarded-access-token": pxe_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": bss_good_path, "headers": {"x-forwarded-access-token": pxe_auth}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": bss_bad_path, "headers": {"x-forwarded-access-token": pxe_auth}}}}}

}

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


  # NMD - Not Allowed
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

test_unauth_role_xforwarded {

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": pals_mock_path, "headers": {"x-forwarded-access-token": unauthorized_role_auth}}}}}

}

# Spire is disabled

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
