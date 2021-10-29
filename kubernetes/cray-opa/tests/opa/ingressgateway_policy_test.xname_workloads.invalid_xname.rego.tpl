# Copyright 2021 Hewlett Packard Enterprise Development LP

package istio.authz
## HOW TO DO UNIT TESTING
# allow.http_status is 403 when the request is rejected due to the default allow.
# allow.http_status is not present the request is successful because the result is true.

hbtb_heartbeat_path = "/apis/hbtd/hmi/v1/heartbeat"
hmnfd_subscribe_path = "/apis/hmnfd/hmi/v1/subscribe"

test_spire_heartbeat_wrong_xname {
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": hbtb_heartbeat_path, "headers": {"authorization": "Bearer {{ .spire.compute.heartbeat }}"}, "body": "{\"Component\": \"valid\",\"Hostname\": \"compute1\",\"NID\": \"0\",\"Status\": \"OK\",\"Timestamp\": \"2021-09-23T22:52:00.955107+00:00\"}" }}}, "parsed_body": { "component": "invalid", "hostname": "compute1", "nid": "0", "status": "OK", "timestamp": "2021-09-23T22:52:00.955107+00:00"}}
  allow.http_status  == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": hbtb_heartbeat_path, "headers": {"authorization": "Bearer {{ .spire.ncn.heartbeat }}"}, "body": "{\"Component\": \"invalid\",\"Hostname\": \"ncn1\",\"NID\": \"0\",\"Status\": \"OK\",\"Timestamp\": \"2021-09-23T22:52:00.955107+00:00\"}" }}}, "parsed_body": { "component": "invalid", "hostname": "compute1", "nid": "0", "status": "OK", "timestamp": "2021-09-23T22:52:00.955107+00:00"}}
}

spire_wrong_xname_sub(sub) {

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/nmd/status/invalid", "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "PUT", "path": "/apis/v2/nmd/status/invalid", "headers": {"authorization": sub}}}}}
  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "GET", "path": "/apis/v2/nmd/dumps?xname=invalid", "headers": {"authorization": sub}}}}}

  allow.http_status == 403 with input as {"attributes": {"request": {"http": {"method": "POST", "path": hmnfd_subscribe_path, "headers": {"authorization": sub}, "body": "{\"Subscriber\": \"handler@invalid\"}"}}}, "parsed_body": {"subscriber": "handler@invalid"}}

}

test_spire_wrong_xname_subs {
  spire_wrong_xname_sub("Bearer {{ .spire.compute.dvs_hmi }}")
  spire_wrong_xname_sub("Bearer {{ .spire.compute.dvs_map }}")
  spire_wrong_xname_sub("Bearer {{ .spire.compute.orca }}")
  spire_wrong_xname_sub("Bearer {{ .spire.ncn.dvs_hmi }}")
  spire_wrong_xname_sub("Bearer {{ .spire.ncn.dvs_map }}")
  spire_wrong_xname_sub("Bearer {{ .spire.ncn.orca }}")
}
