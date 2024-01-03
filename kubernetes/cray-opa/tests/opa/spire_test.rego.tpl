# Copyright 2021-2023 Hewlett Packard Enterprise Development LP

package istio.authz
## HOW TO DO UNIT TESTING
# allow.http_status is 403 when the request is rejected due to the default allow.
# allow.http_status is not present the request is successful because the result is true.

cfs_mock_path = "/apis/cfs/components/mock"
cfs_ncn_mock_path = "/apis/cfs/components/ncnw001"
cfs_compute_mock_path = "/apis/cfs/components/x1"
cps_mock_path = "/apis/v2/cps/mock"
cos_config_mock_path = "/apis/v2/cos/mock"
hbtb_heartbeat_path = "/apis/hbtd/hmi/v1/heartbeat"
nmd_mock_path = "/apis/v2/nmd/status"
smd_statecomponents_path = "/apis/smd/hsm/v2/State/Components"
smd_softwarestatus_compute_path = "/apis/smd/hsm/v2/State/Components/x1/SoftwareStatus"
smd_softwarestatus_ncn_path = "/apis/smd/hsm/v2/State/Components/ncnw001/SoftwareStatus"
smd_softwarestatus_invalid_path = "/apis/smd/hsm/v2/State/Components/invalid/SoftwareStatus"
hmnfd_subscribe_path = "/apis/hmnfd/hmi/v1/subscribe"
hmnfd_subscriptions_path = "/apis/hmnfd/hmi/v1/subscriptions"
pals_mock_path = "/apis/pals/v1/mock"

# Tests for denying access to pals mock path for ckdump sub

unauthorized_role_auth = "Bearer {{ .spire.compute.ckdump }}"

test_unauth_role {

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": pals_mock_path, "headers": {"authorization": unauthorized_role_auth}}}}}

}

# SPIRE Tests

spire_correct_ncn_sub(sub) {

  # NMD - Allowed

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/nmd/status/ncnw001", "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/v2/nmd/status/ncnw001", "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/nmd/status", "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/nmd/healthz/live", "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/nmd/healthz/ready", "headers": {"authorization": sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": nmd_mock_path, "headers": {"authorization": sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": nmd_mock_path, "headers": {"authorization": sub}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": smd_statecomponents_path, "headers": {"authorization": sub}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": smd_statecomponents_path, "headers": {"authorization": sub}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": smd_softwarestatus_ncn_path, "headers": {"authorization": sub}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": hmnfd_subscriptions_path, "headers": {"authorization": sub}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": hmnfd_subscriptions_path, "headers": {"authorization": sub}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": hmnfd_subscribe_path, "headers": {"authorization": sub}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": hmnfd_subscribe_path, "headers": {"authorization": sub}, "body": "{\"Subscriber\": \"handler@ncnw001\"}"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": hmnfd_subscribe_path, "headers": {"authorization": sub}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/hmnfd/hmi/v2/subscriptions/ncnw001", "headers": {"authorization": sub}, "body": "{\"Subscriber\": \"handler@ncnw001\"}"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/hmnfd/hmi/v2/subscriptions/ncnw001/agents/agent1", "headers": {"authorization": sub}, "body": "{\"Subscriber\": \"handler@ncnw001\"}"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": "/apis/hmnfd/hmi/v2/subscriptions/ncnw001/agents/agent1", "headers": {"authorization": sub}, "body": "{\"Subscriber\": \"handler@ncnw001\"}"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/hmnfd/hmi/v2/subscriptions/ncnw001/agents/agent1", "headers": {"authorization": sub}, "body": "{\"Subscriber\": \"handler@ncnw001\"}"}}}}

  # Validate that we're not allowing any method with a valid aud through
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": cfs_ncn_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": cfs_ncn_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": cfs_ncn_mock_path, "headers": {"authorization": sub}}}}}

  # Validate that only CFS can access
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": cfs_ncn_mock_path, "headers": {"authorization": sub}}}}}

  # Validate that DVS can access SoftwareStatus
  # not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": "/apis/smd/hsm/v2/State/Components/ncnw001/SoftwareStatus", "headers": {"authorization": sub}}}}}

}

spire_correct_compute_sub(sub) {

  # NMD - Allowed

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/v2/nmd/status/x1", "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/nmd/status/x1", "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/nmd/status", "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/nmd/healthz/live", "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/nmd/healthz/ready", "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": nmd_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": nmd_mock_path, "headers": {"authorization": sub}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": smd_statecomponents_path, "headers": {"authorization": sub}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": smd_statecomponents_path, "headers": {"authorization": sub}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": smd_softwarestatus_compute_path, "headers": {"authorization": sub}}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": hmnfd_subscriptions_path, "headers": {"authorization": sub}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": hmnfd_subscriptions_path, "headers": {"authorization": sub}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": hmnfd_subscribe_path, "headers": {"authorization": sub}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": hmnfd_subscribe_path, "headers": {"authorization": sub}, "body": "{\"Subscriber\": \"handler@x1\"}"}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": hmnfd_subscribe_path, "headers": {"authorization": sub}}}}}

  # Validate that we're not allowing any method with a valid aud through
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": cfs_compute_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": cfs_compute_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": cfs_compute_mock_path, "headers": {"authorization": sub}}}}}

  # Validate that only CFS can access
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": cfs_compute_mock_path, "headers": {"authorization": sub}}}}}
}


test_spire_ncn_subs {
  spire_correct_ncn_sub("Bearer {{ .spire.ncn.dvs_hmi }}")
  spire_correct_ncn_sub("Bearer {{ .spire.ncn.dvs_map }}")
  spire_correct_ncn_sub("Bearer {{ .spire.ncn.orca }}")
}

test_spire_compute_subs {
  spire_correct_compute_sub("Bearer {{ .spire.compute.dvs_hmi }}")
  spire_correct_compute_sub("Bearer {{ .spire.compute.dvs_map }}")
  spire_correct_compute_sub("Bearer {{ .spire.compute.orca }}")
}

test_spire_heartbeat {
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/hbtd/hmi/v1/heartbeat/x1", "headers": {"authorization": "Bearer {{ .spire.compute.heartbeat }}"}, "body": "{\"Component\": \"x1\",\"Hostname\": \"compute1\",\"NID\": \"0\",\"Status\": \"OK\",\"Timestamp\": \"2021-09-23T22:52:00.955107+00:00\"}" }}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/hbtd/hmi/v1/heartbeat/ncnw001", "headers": {"authorization": "Bearer {{ .spire.ncn.heartbeat }}"}, "body": "{\"Component\": \"ncnw001\",\"Hostname\": \"ncn1\",\"NID\": \"0\",\"Status\": \"OK\",\"Timestamp\": \"2021-09-23T22:52:00.955107+00:00\"}" }}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/hbtd/hmi/v1/params", "headers": {"authorization": "Bearer {{ .spire.compute.heartbeat }}"}}}}}
}

test_spire_cfs {
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": cfs_ncn_mock_path, "headers": {"authorization": "Bearer {{ .spire.ncn.cfs_state_reporter }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": cfs_compute_mock_path, "headers": {"authorization": "Bearer {{ .spire.compute.cfs_state_reporter }}" }}}}}
}

spire_cps(spire_sub) {
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/cps/transports?transport=dvs", "headers": {"authorization": spire_sub}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/v2/cps/contents", "headers": {"authorization": spire_sub}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/v2/cps/transports", "headers": {"authorization": spire_sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": cps_mock_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cps_mock_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cps_mock_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/v2/cps/deployment", "headers": {"authorization": spire_sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/cos/configs", "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cos_config_mock_path, "headers": {"authorization": spire_sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/v2/nmd/status/x1", "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": nmd_mock_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": nmd_mock_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": nmd_mock_path, "headers": {"authorization": spire_sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cfs_mock_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cfs_mock_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": cfs_mock_path, "headers": {"authorization": spire_sub}}}}}
}

test_spire_cps {
  spire_cps("Bearer {{ .spire.compute.cpsmount }}")
  spire_cps("Bearer {{ .spire.compute.cpsmount_helper }}")
  spire_cps("Bearer {{ .spire.ncn.cpsmount }}")
  spire_cps("Bearer {{ .spire.ncn.cpsmount_helper }}")
}

spire_ckdump_compute(sub) {

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/v2/nmd/status/x1", "headers": {"authorization": sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": nmd_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": nmd_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": nmd_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": nmd_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/nmd/dumps?xname=x1", "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/v2/nmd/dumps", "headers": {"authorization": sub}, "body": "{ \"xname\": [ \"x1\" ] }"}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/nmd/sdf/dump/discovery", "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/nmd/sdf/dump/targets", "headers": {"authorization": sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cfs_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cfs_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": cfs_mock_path, "headers": {"authorization": sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cps_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cps_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": cps_mock_path, "headers": {"authorization": sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cos_config_mock_path, "headers": {"authorization": sub}}}}}
}


spire_ckdump_ncn(sub) {

  allow.http_status == 403  with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/v2/nmd/status/x1", "headers": {"authorization": sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/nmd/sdf/dump/discovery", "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/nmd/sdf/dump/targets", "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/nmd/dumps?xname=ncnw001", "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/v2/nmd/dumps", "headers": {"authorization": sub}, "body": "{ \"xname\": [ \"ncnw001\" ] }"}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": nmd_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": nmd_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": nmd_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": nmd_mock_path, "headers": {"authorization": sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cfs_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cfs_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": cfs_mock_path, "headers": {"authorization": sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cps_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": cps_mock_path, "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": cps_mock_path, "headers": {"authorization": sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": cos_config_mock_path, "headers": {"authorization": sub}}}}}
}

test_spire_ckdump_compute {
  spire_ckdump_compute("Bearer {{ .spire.compute.ckdump }}")
  spire_ckdump_compute("Bearer {{ .spire.compute.ckdump_helper }}")
}

test_spire_ckdump_ncn {
  spire_ckdump_ncn("Bearer {{ .spire.ncn.ckdump }}")
  spire_ckdump_ncn("Bearer {{ .spire.ncn.ckdump_helper }}")
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

test_tpm_provisioner {
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/tpm-provisioner/authorize?xname=ncnw001&type=ncn", "headers": {"authorization": "Bearer {{ .spire.ncn.tpm_provisioner }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/tpm-provisioner/authorize?xname=x1&type=compute", "headers": {"authorization": "Bearer {{ .spire.compute.tpm_provisioner }}" }}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/tpm-provisioner/challenge/request", "headers": {"authorization": "Bearer {{ .spire.ncn.tpm_provisioner }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/tpm-provisioner/challenge/submit", "headers": {"authorization": "Bearer {{ .spire.ncn.tpm_provisioner }}" }}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/tpm-provisioner/challenge/request", "headers": {"authorization": "Bearer {{ .spire.compute.tpm_provisioner }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/tpm-provisioner/challenge/submit", "headers": {"authorization": "Bearer {{ .spire.compute.tpm_provisioner }}" }}}}}


  # tpm-provisioner role should not have access to white list API
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/tpm-provisioner/whitelist/get", "headers": {"authorization": "Bearer {{ .spire.ncn.tpm_provisioner }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/tpm-provisioner/whitelist/get", "headers": {"authorization": "Bearer {{ .spire.compute.tpm_provisioner }}" }}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/tpm-provisioner/whitelist/add", "headers": {"authorization": "Bearer {{ .spire.ncn.tpm_provisioner }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/tpm-provisioner/whitelist/add", "headers": {"authorization": "Bearer {{ .spire.compute.tpm_provisioner }}" }}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/tpm-provisioner/whitelist/remove", "headers": {"authorization": "Bearer {{ .spire.ncn.tpm_provisioner }}" }}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/tpm-provisioner/whitelist/remove", "headers": {"authorization": "Bearer {{ .spire.compute.tpm_provisioner }}" }}}}}
}

test_wlm {
  spire_sub = "Bearer {{ .spire.compute.wlm }}"

  # CAPMC - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/get_xname_status", "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/xname_reinit", "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/xname_on", "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/xname_off", "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/get_power_cap", "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/get_power_cap_capabilities", "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/capmc/capmc/v1/set_power_cap", "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/capmc/capmc/v1/set_power_cap", "headers": {"authorization": spire_sub}}}}}
  # PCS - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/power-control/v1/power-status?xname=test", "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/power-control/v1/transitions", "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": "/apis/power-control/v1/power-cap", "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/power-control/v1/transitions/test", "headers": {"authorization": spire_sub}}}}}
  # BOS - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/bos/v2/applystaged", "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/bos/v1/session", "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/bos/v1/session", "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/bos/v1/session", "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PATCH", "path": "/apis/bos/v1/session", "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/bos/v1/session", "headers": {"authorization": spire_sub}}}}}
  # SMD - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": smd_statecomponents_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": smd_statecomponents_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": smd_statecomponents_path, "headers": {"authorization": spire_sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": smd_statecomponents_path, "headers": {"authorization": spire_sub}}}}}
  # VNID - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/vnid/fabric/vnis", "headers": {"authorization": spire_sub}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/vnid/fabric/vnis", "headers": {"authorization": spire_sub}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/vnid/fabric/vnis", "headers": {"authorization": spire_sub}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/vnid/fabric/vnis", "headers": {"authorization": spire_sub}}}}}
  # VNID - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/vnid/fabric/vnis", "headers": {"authorization": spire_sub}}}}}
  # jackaloped - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/jackaloped/fabric/nics", "headers": {"authorization": spire_sub}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/jackaloped/fabric/nics", "headers": {"authorization": spire_sub}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/jackaloped/fabric/nics", "headers": {"authorization": spire_sub}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/jackaloped/fabric/nics", "headers": {"authorization": spire_sub}}}}}
  # jackaloped - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/jackaloped/fabric/nics", "headers": {"authorization": spire_sub}}}}}
  # ogopogod - allowed
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/ogopogod/partitions", "headers": {"authorization": spire_sub}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "HEAD", "path": "/apis/ogopogod/partitions", "headers": {"authorization": spire_sub}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/ogopogod/partitions", "headers": {"authorization": spire_sub}}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "DELETE", "path": "/apis/ogopogod/partitions", "headers": {"authorization": spire_sub}}}}}
  # ogopogod - not allowed
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/ogopogod/partitions", "headers": {"authorization": spire_sub}}}}}
}

test_tpm_provisioner_cray_spire {
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/tpm-provisioner/authorize?xname=x1&type=compute", "headers": {"authorization": "Bearer {{ .spire.compute.cray_tpm_provisioner }}" }}}}}

  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/tpm-provisioner/challenge/request", "headers": {"authorization": "Bearer {{ .spire.compute.cray_tpm_provisioner }}" }}}}}
  not allow.http_status with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/tpm-provisioner/challenge/submit", "headers": {"authorization": "Bearer {{ .spire.compute.cray_tpm_provisioner }}" }}}}}

  # tpm-provisioner role should not have access to white list API
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/tpm-provisioner/whitelist/get", "headers": {"authorization": "Bearer {{ .spire.compute.cray_tpm_provisioner }}" }}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/tpm-provisioner/whitelist/add", "headers": {"authorization": "Bearer {{ .spire.compute.cray_tpm_provisioner }}" }}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": "/apis/tpm-provisioner/whitelist/remove", "headers": {"authorization": "Bearer {{ .spire.compute.cray_tpm_provisioner }}" }}}}}
}
