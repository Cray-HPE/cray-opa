{{- /*
Copyright 2021,2022 Hewlett Packard Enterprise Development LP
*/ -}}
{{ define "ingressgateway.policy" }}

# Istio Ingress Gateway OPA Policy
package istio.authz

import input.attributes.request.http as http_request

# Default return a 403 unless any of the allows are true
default allow = {
  "allowed": false,
  "headers": {"x-ext-auth-allow": "no"},
  "body": "Unauthorized Request",
  "http_status": 403
}

# Whitelist traffic to the Neuxs web UI since it uses Keycloak for authentication.
allow {
    http_request.headers["x-envoy-decorator-operation"] = "nexus.nexus.svc.cluster.local:80/*"
}

# Whitelist traffic to the Grafana web UI since it uses Keycloak for authentication.
allow {
    http_request.headers["x-envoy-decorator-operation"] = "cray-sysmgmt-health-grafana.sysmgmt-health.svc.cluster.local:80/*"
}

# Whitelist traffic to SMA Grafana web UI since it uses Keycloak for authentication.
allow {
    http_request.headers["x-envoy-decorator-operation"] = "sma-grafana.services.svc.cluster.local:3000/*"
}

# Whitelist traffic to SMA Kibana web UI since it uses Keycloak for authentication.
allow {
    http_request.headers["x-envoy-decorator-operation"] = "sma-kibana.services.svc.cluster.local:5601/*"
}

# The path being requested from the user. When the envoy filter is configured for
# SIDECAR_INBOUND this is: http_request.headers["x-envoy-original-path"].
# When configured for GATEWAY this is http_request.path
original_path = o_path {
    o_path := http_request.path
}

original_body = o_path {
    o_path := http_request.body
}

# Whitelist Keycloak, since those services enable users to login and obtain
# JWTs. Spire endpoints and vcs are also enabled here. Legacy services to be
# migrated or removed:
#
#     * VCS/Gitea
#
allow { startswith(original_path, "/keycloak") }
allow { startswith(original_path, "/vcs") }
# Allow cloud-init endpoints, as we do validation based on incoming IP.
# In the future, these requests will come in via the TOR switches and ideally
# not through the 'front door'.   This is an expansion to BSS.
allow { startswith(original_path, "/meta-data") }
allow { startswith(original_path, "/user-data") }
allow { startswith(original_path, "/phone-home") }

# Whitelist Nexus repository pods. Nexus uses it's own RBAC so open
# all commands. Keycloak Gatekeeper is used to pass the tokens through
allow { startswith(original_path, "/repository") }
allow { startswith(original_path, "/v2") }
allow { startswith(original_path, "/service/rest") }

# Whitelist Capsules UI. The Capsules UI starts at a login page which validates user access by retrieving a valid
# token from keycloak with the provided credentials.
allow { startswith(original_path, "/capsules/") }

# Whitelist gozerd (does its own MUNGE auth)
allow { startswith(original_path, "/apis/gozerd/") }

{{- if not .Values.opa.requireHeartbeatToken }}
# Allow heartbeats without requiring a spire token
allow { startswith(original_path, "/apis/hbtd/hmi/v1/heartbeat") }
{{- end }}

# This actually checks the JWT token passed in
# has access to the endpoint requested
allow {
    roles_for_user[r]
    required_roles[r]
    # exclude argo ui server
    not http_request.headers["x-envoy-decorator-operation"] = "cray-nls-argo-workflows-server.argo.svc.cluster.local:2746/*"
}

# Handle argo UI server
#   - READ-only for admin
#   - Block access for all other users
allow {
  http_request.headers["x-envoy-decorator-operation"] = "cray-nls-argo-workflows-server.argo.svc.cluster.local:2746/*"
  parsed_kc_token.payload.resource_access.shasta.roles[_] = "admin"
  http_request.method = "GET"
}


{{- if .Values.opa.xnamePolicy.enabled }}
# Validate claims for SPIRE issued JWT tokens with xname support
allow {
    s :=  replace(parsed_spire_token.payload.sub, parsed_spire_token.xname, "XNAME")

    # Test subject matches destination
    perm := sub_match[s][_]
    perm.method = http_request.method
    re_match(perm.path, original_path)
}

{{- else }}
# Validate claims for SPIRE issued JWT tokens
allow {
    # Parse subject
    s := parsed_spire_token.payload.sub

    # Test subject matches destination
    perm := sub_match[s][_]
    perm.method = http_request.method
    re_match(perm.path, original_path)
}
{{- end }}

# Check if there is an authorization header and split the type from token
found_auth = {"type": a_type, "token": a_token} {
    [a_type, a_token] := split(http_request.headers.authorization, " ")
}

# Check if there is a forwarded access token header and split the type from token
found_auth = {"type": a_type, "token": a_token} {
  a_token := http_request.headers["x-forwarded-access-token"]
  [_, payload, _] := io.jwt.decode(a_token)
  a_type := payload.typ
}

# If the auth type is bearer, decode the JWT
parsed_kc_token = {"payload": payload} {
    found_auth.type == "Bearer"
    response := http.send({"method": "get", "url": "{{ .Values.jwtValidation.keycloak.jwksUri }}", "cache": true, "tls_ca_cert_file": "/jwtValidationFetchTls/certificate_authority.crt"})
    [_, _, payload] := io.jwt.decode_verify(found_auth.token, {"cert": response.raw_body, "aud": "shasta"})

    # Verify that the issuer is as expected.
    allowed_issuers := [
{{- range $key, $value := .Values.ingresses.ingressgateway.issuers }}
      "{{ $value }}",
{{- end }}
    ]
    allowed_issuers[_] = payload.iss
}

{{- if .Values.opa.xnamePolicy.enabled }}
# If the auth type is bearer, decode the JWT
parsed_spire_token = {"payload": payload, "xname": xname} {
    found_auth.type == "Bearer"
    response := http.send({"method": "get", "url": "{{ .Values.jwtValidation.spire.jwksUri }}", "cache": true, "tls_ca_cert_file": "/jwtValidationFetchTls/certificate_authority.crt"})
    [_, _, payload] := io.jwt.decode_verify(found_auth.token, {"cert": response.raw_body, "aud": "system-compute"})

    # Verify that the issuer is as expected.
    allowed_issuers := [
{{- range $key, $value := .Values.jwtValidation.spire.issuers }}
      "{{ $value }}",
{{- end }}
    ]
    allowed_issuers[_] = payload.iss

    xname := regex.split("/", payload.sub)[4]
}
{{- else }}
# If the auth type is bearer, decode the JWT
parsed_spire_token = {"payload": payload} {
    found_auth.type == "Bearer"
    response := http.send({"method": "get", "url": "{{ .Values.jwtValidation.spire.jwksUri }}", "cache": true, "tls_ca_cert_file": "/jwtValidationFetchTls/certificate_authority.crt"})
    [_, _, payload] := io.jwt.decode_verify(found_auth.token, {"cert": response.raw_body, "aud": "system-compute"})

    # Verify that the issuer is as expected.
    allowed_issuers := [
{{- range $key, $value := .Values.jwtValidation.spire.issuers }}
      "{{ $value }}",
{{- end }}
    ]
    allowed_issuers[_] = payload.iss
}
{{- end }}

# Get the users roles from the JWT token
roles_for_user[r] {
    r := parsed_kc_token.payload.resource_access.shasta.roles[_]
}

# Determine if the path/verb requests is authorized based on the JWT roles
required_roles[r] {
    perm := role_perms[r][_]
    perm.method = http_request.method
    re_match(perm.path, original_path)
}


allowed_methods := {
  "user": [
      # UAS
      {"method": "GET", "path": `^/apis/uas-mgr/v1/$`}, # Get UAS API Version
      {"method": "GET", "path": `^/apis/uas-mgr/v1/uas$`}, # List UAIs for current user
      {"method": "POST", "path": `^/apis/uas-mgr/v1/uas$`}, # Create a UAI for current user
      {"method": "DELETE", "path": `^/apis/uas-mgr/v1/uas$`}, # Delete a UAI(s) for current user
      {"method": "GET", "path": `^/apis/uas-mgr/v1/images$`}, # List Available UAI Images
      {"method": "GET", "path": `^/apis/uas-mgr/v1/mgr-info$`}, # Get UAS Service Version
      # PALS
      {"method": "GET", "path": `^/apis/pals/v1/.*$`}, # All PALs API Calls - GET
      {"method": "PUT", "path": `^/apis/pals/v1/.*$`}, # All PALs API Calls - PUT
      {"method": "POST", "path": `^/apis/pals/v1/.*$`}, # All PALs API Calls - POST
      {"method": "DELETE", "path": `^/apis/pals/v1/.*$`}, # All PALs API Calls - DELETE
      {"method": "HEAD", "path": `^/apis/pals/v1/.*$`}, # All PALs API Calls - HEAD
      {"method": "PATCH", "path": `^/apis/pals/v1/.*$`}, # All PALs API Calls - PATCH
      # Analytics Capsules
      {"method": "DELETE", "path": `^/apis/capsules/.*$`}, # All Capsules API Calls - DELETE
      {"method": "GET", "path": `^/apis/capsules/.*$`}, # All Capsules API Calls - GET
      {"method": "HEAD", "path": `^/apis/capsules/.*$`}, # All Capsules API Calls - HEAD
      {"method": "PATCH", "path": `^/apis/capsules/.*$`}, # All Capsules API Calls - PATCH
      {"method": "POST", "path": `^/apis/capsules/.*$`}, # All Capsules API Calls - POST
      {"method": "PUT", "path": `^/apis/capsules/.*$`}, # All Capsules API Calls - PUT
      # SMA
      {"method": "GET", "path": `^/apis/sma-telemetry-api/.*$`}, # All SMA telemetry API Calls - GET
  ],
  "system-pxe": [

   #BSS -> computes need to retrieve boot scripts
      {"method": "GET",  "path": `^/apis/bss/boot/v1/bootscript.*$`},
      {"method": "HEAD",  "path": `^/apis/bss/boot/v1/bootscript.*$`},
  ],
  "system-compute": [
    {"method": "PATCH",  "path": `^/apis/bos/v./components/.*$`},

    {"method": "PATCH",  "path": `^/apis/cfs/components/.*$`},
    {"method": "PATCH",  "path": `^/apis/cfs/v./components/.*$`},

    {"method": "GET",  "path": `^/apis/v2/cps/transports`},
    {"method": "POST",  "path": `^/apis/v2/cps/contents$`},
    {"method": "POST",  "path": `^/apis/v2/cps/transports$`},

    {"method": "PUT",  "path": `^/apis/v2/nmd/status/.*$`},

    #SMD -> GET everything, DVS needs SoftwareStatus.  REVOKED permission to update BulkSoftwareStatus
    {"method": "GET",  "path": `^/apis/smd/hsm/v2/.*$`},
    {"method": "HEAD",  "path": `^/apis/smd/hsm/v2/.*$`},
    #very naieve xname regex: [a-zA-Z0-9]* #make sure someone cant redirect the path with a /
    {"method": "PATCH",  "path": `^/apis/smd/hsm/v2/State/Components/[a-zA-Z0-9]*/SoftwareStatus$`},
    #HMNFD -> subscribe only, cannot create state change notifications
    {"method": "GET",  "path": `^/apis/hmnfd/hmi/v1/subscriptions$`},
    {"method": "HEAD",  "path": `^/apis/hmnfd/hmi/v1/subscriptions$`},
    {"method": "PATCH",  "path": `^/apis/hmnfd/hmi/v1/subscribe$`},
    {"method": "POST",  "path": `^/apis/hmnfd/hmi/v1/subscribe$`},
    {"method": "DELETE",  "path": `^/apis/hmnfd/hmi/v1/subscribe$`},
    {"method": "GET", "path": `^/apis/hmnfd/hmi/v2/subscriptions/.*$`},
    {"method": "POST", "path": `^/apis/hmnfd/hmi/v2/subscriptions/.*$`},
    {"method": "PATCH", "path": `^/apis/hmnfd/hmi/v2/subscriptions/.*$`},
    {"method": "DELETE", "path": `^/apis/hmnfd/hmi/v2/subscriptions/.*$`},
    #HBTD -> allow a compute to send a heartbeat
    {"method": "POST", "path": `^/apis/hbtd/hmi/v1/heartbeat$`},
    {"method": "POST", "path": `^/apis/hbtd/hmi/v1/heartbeat/.*$`},
    {"method": "GET", "path": `^/apis/hbtd/hmi/v1/params$`},


  ],
  "wlm": [
      # CAPMC - power capping and power control; eventually this will need to add PCS
        ## CAPMC -> Xnames
      {"method": "POST", "path": `^/apis/capmc/capmc/v1/get_xname_status$`},
      {"method": "POST", "path": `^/apis/capmc/capmc/v1/xname_reinit$`},
      {"method": "POST", "path": `^/apis/capmc/capmc/v1/xname_on$`},
      {"method": "POST", "path": `^/apis/capmc/capmc/v1/xname_off$`},
        ## CAPMC -> Power Capping
      {"method": "POST", "path": `^/apis/capmc/capmc/v1/get_power_cap$`},
      {"method": "POST", "path": `^/apis/capmc/capmc/v1/get_power_cap_capabilities$`},
      {"method": "POST", "path": `^/apis/capmc/capmc/v1/set_power_cap$`},
      # BOS - node boot
      {"method": "GET", "path": `^/apis/bos/.*$`},
      {"method": "HEAD", "path": `^/apis/bos/.*$`},
      {"method": "POST", "path": `^/apis/bos/.*$`},
      {"method": "PATCH", "path": `^/apis/bos/.*$`},
      {"method": "DELETE", "path": `^/apis/bos/.*$`},
      # SMD - hardware state query
      {"method": "GET",  "path": `^/apis/smd/hsm/v2/.*$`},
      {"method": "HEAD",  "path": `^/apis/smd/hsm/v2/.*$`},
      # FC - VNI reservation
      {"method": "GET", "path": `^/apis/fc/.*$`},
      {"method": "HEAD", "path": `^/apis/fc/.*$`},
      {"method": "POST", "path": `^/apis/fc/.*$`},
      {"method": "PUT", "path": `^/apis/fc/.*$`},
      {"method": "DELETE", "path": `^/apis/fc/.*$`},
      # VNID - VNI reservation
      {"method": "GET", "path": `^/apis/vnid/.*$`},
      {"method": "HEAD", "path": `^/apis/vnid/.*$`},
      {"method": "POST", "path": `^/apis/vnid/.*$`},
      {"method": "DELETE", "path": `^/apis/vnid/.*$`},
      # jackaloped - scalable startup
      {"method": "GET", "path": `^/apis/jackaloped/.*$`},
      {"method": "HEAD", "path": `^/apis/jackaloped/.*$`},
      {"method": "POST", "path": `^/apis/jackaloped/.*$`},
      {"method": "DELETE", "path": `^/apis/jackaloped/.*$`},
  ],
  "admin": [
      {"method": "GET",  "path": `.*`},
      {"method": "PUT",  "path": `.*`},
      {"method": "POST",  "path": `.*`},
      {"method": "DELETE",  "path": `.*`},
      {"method": "PATCH",  "path": `.*`},
      {"method": "HEAD",  "path": `.*`},
  ],
  "ckdump": [
      {"method": "PUT",  "path": `^/apis/v2/nmd/status/.*$`},
  ],
  "monitor-ro": [
      # SMA
      {"method": "GET", "path": `^/apis/sma-telemetry-api/.*$`}, # All SMA telemetry API Calls - GET
  ],
}

# Our list of endpoints we accept based on roles.
# The admin roll can make any call.
role_perms = {
    "user": allowed_methods["user"],
    "system-pxe": allowed_methods["system-pxe"],
    "system-compute": allowed_methods["system-compute"],
    "wlm": allowed_methods["wlm"],
    "admin": allowed_methods["admin"],
    "monitor-ro": allowed_methods["monitor-ro"],
}

{{- if .Values.opa.xnamePolicy.enabled }}
spire_methods := {
  "bos": [
  {{- if .Values.opa.xnamePolicy.bos }}
    {"method": "PATCH", "path": sprintf("^/apis/bos/v./components/%v$", [parsed_spire_token.xname])},
  {{- else }}
    {"method": "PATCH", "path": `^/apis/bos/v./components/.*$`},
  {{- end }}
  ],
  "cfs": [
  {{- if .Values.opa.xnamePolicy.cfs }}
    {"method": "PATCH", "path": sprintf("^/apis/cfs/components/%v$", [parsed_spire_token.xname])},
    {"method": "PATCH", "path": sprintf("^/apis/cfs/v./components/%v$", [parsed_spire_token.xname])},
  {{- else }}
    {"method": "PATCH", `^/apis/cfs/components/.*$`},
    {"method": "PATCH", `^/apis/cfs/v./components/.*$`},
  {{- end }}
  ],
  "cps": [
    {"method": "GET",  "path": `^/apis/v2/cps/transports`},
    {"method": "POST",  "path": `^/apis/v2/cps/contents$`},
    {"method": "POST",  "path": `^/apis/v2/cps/transports$`},
  ],
  "dvs": [

    {{- if .Values.opa.xnamePolicy.dvs }}
    {"method": "GET", "path": sprintf("^/apis/hmnfd/hmi/v2/subscriptions/%v$", [parsed_spire_token.xname])},
    {"method": "POST", "path": sprintf("^/apis/hmnfd/hmi/v2/subscriptions/%v/agents/", [parsed_spire_token.xname])},
    {"method": "PATCH", "path": sprintf("^/apis/hmnfd/hmi/v2/subscriptions/%v/agents/", [parsed_spire_token.xname])},
    {"method": "DELETE", "path": sprintf("^/apis/hmnfd/hmi/v2/subscriptions/%v/agents/", [parsed_spire_token.xname])},
    {{- else }}
    {"method": "GET", "path": `^/apis/hmnfd/hmi/v2/subscriptions/.*$`},
    {"method": "POST", "path": `^/apis/hmnfd/hmi/v2/subscriptions/.*$`},
    {"method": "PATCH", "path": `^/apis/hmnfd/hmi/v2/subscriptions/.*$`},
    {"method": "DELETE", "path": `^/apis/hmnfd/hmi/v2/subscriptions/.*$`},
    {{- end }}
    # These pass xnames via POST. This will be removed once the v2 API is being used.
    {"method": "POST", "path": `^/apis/hmnfd/hmi/v1/subscribe$`},

    #SMD -> GET everything,  DVS needs SoftwareStatus.  REVOKED permission to update BulkSoftwareStatus
    {"method": "GET",   "path": `^/apis/smd/hsm/v2/.*$`},
    {"method": "HEAD",  "path": `^/apis/smd/hsm/v2/.*$`},
    {"method": "PATCH", "path": sprintf("^/apis/smd/hsm/v2/State/Components/%v/SoftwareStatus$", [parsed_spire_token.xname])},

    #HMNFD -> subscribe only, cannot create state change notifications
    {"method": "GET",   "path": `^/apis/hmnfd/hmi/v1/subscriptions$`},
    {"method": "HEAD",  "path": `^/apis/hmnfd/hmi/v1/subscriptions$`},
    {"method": "PATCH", "path": `^/apis/hmnfd/hmi/v1/subscribe$`},
    {"method": "DELETE","path": `^/apis/hmnfd/hmi/v1/subscribe$`},
  ],
  "ckdump": [
    {{- if .Values.opa.xnamePolicy.ckdump }}
      {"method": "PUT", "path": sprintf("^/apis/v2/nmd/status/%v$", [parsed_spire_token.xname])},
    {{- else }}
      {"method": "PUT", "path": `^/apis/v2/nmd/status/.*$`},
    {{- end }}
  ],
  "wlm": [
      # CAPMC - power capping and power control; eventually this will need to add PCS
        ## CAPMC -> Xnames
      {"method": "POST", "path": `^/apis/capmc/capmc/v1/get_xname_status$`},
      {"method": "POST", "path": `^/apis/capmc/capmc/v1/xname_reinit$`},
      {"method": "POST", "path": `^/apis/capmc/capmc/v1/xname_on$`},
      {"method": "POST", "path": `^/apis/capmc/capmc/v1/xname_off$`},
        ## CAPMC -> Power Capping
      {"method": "POST", "path": `^/apis/capmc/capmc/v1/get_power_cap$`},
      {"method": "POST", "path": `^/apis/capmc/capmc/v1/get_power_cap_capabilities$`},
      {"method": "POST", "path": `^/apis/capmc/capmc/v1/set_power_cap$`},
      # BOS - node boot
      {"method": "GET", "path": `^/apis/bos/.*$`},
      {"method": "HEAD", "path": `^/apis/bos/.*$`},
      {"method": "POST", "path": `^/apis/bos/.*$`},
      {"method": "PATCH", "path": `^/apis/bos/.*$`},
      {"method": "DELETE", "path": `^/apis/bos/.*$`},
      # SMD - hardware state query
      {"method": "GET",  "path": `^/apis/smd/hsm/v2/.*$`},
      {"method": "HEAD",  "path": `^/apis/smd/hsm/v2/.*$`},
      # VNID - VNI reservation
      {"method": "GET", "path": `^/apis/vnid/.*$`},
      {"method": "HEAD", "path": `^/apis/vnid/.*$`},
      {"method": "POST", "path": `^/apis/vnid/.*$`},
      {"method": "DELETE", "path": `^/apis/vnid/.*$`},
      # jackaloped - scalable startup
      {"method": "GET", "path": `^/apis/jackaloped/.*$`},
      {"method": "HEAD", "path": `^/apis/jackaloped/.*$`},
      {"method": "POST", "path": `^/apis/jackaloped/.*$`},
      {"method": "DELETE", "path": `^/apis/jackaloped/.*$`},
  ],
  "heartbeat": [
    {{- if .Values.opa.xnamePolicy.heartbeat }}
     {"method": "POST", "path": sprintf("^/apis/hbtd/hmi/v1/heartbeat/%v$", [parsed_spire_token.xname])},
    {{- else }}
     {"method": "POST", "path": `^/apis/hbtd/hmi/v1/heartbeat$`},
     {"method": "POST", "path": `^/apis/hbtd/hmi/v1/heartbeat/.*$`},
    {{- end }}
     {"method": "GET", "path": `^/apis/hbtd/hmi/v1/params$`},

  ]
}
sub_match = {
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/compute/XNAME/workload/bos-state-reporter": spire_methods["bos"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/compute/XNAME/workload/cfs-state-reporter": spire_methods["cfs"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/compute/XNAME/workload/ckdump": spire_methods["ckdump"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/compute/XNAME/workload/ckdump_helper": spire_methods["ckdump"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/compute/XNAME/workload/cpsmount": spire_methods["cps"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/compute/XNAME/workload/cpsmount_helper": spire_methods["cps"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/compute/XNAME/workload/dvs-hmi": spire_methods["dvs"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/compute/XNAME/workload/dvs-map": spire_methods["dvs"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/compute/XNAME/workload/heartbeat": spire_methods["heartbeat"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/compute/XNAME/workload/orca": spire_methods["dvs"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/compute/XNAME/workload/wlm": spire_methods["wlm"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/ncn/XNAME/workload/bos-state-reporter": spire_methods["bos"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/ncn/XNAME/workload/cfs-state-reporter": spire_methods["cfs"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/ncn/XNAME/workload/cpsmount": spire_methods["cps"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/ncn/XNAME/workload/cpsmount_helper": spire_methods["cps"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/ncn/XNAME/workload/dvs-hmi": spire_methods["dvs"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/ncn/XNAME/workload/dvs-map": spire_methods["dvs"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/ncn/XNAME/workload/heartbeat": spire_methods["heartbeat"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/ncn/XNAME/workload/orca": spire_methods["dvs"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/storage/XNAME/workload/cfs-state-reporter": spire_methods["cfs"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/storage/XNAME/workload/heartbeat": spire_methods["heartbeat"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/uan/XNAME/workload/bos-state-reporter": spire_methods["bos"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/uan/XNAME/workload/cfs-state-reporter": spire_methods["cfs"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/uan/XNAME/workload/ckdump": spire_methods["ckdump"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/uan/XNAME/workload/ckdump_helper": spire_methods["ckdump"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/uan/XNAME/workload/cpsmount": spire_methods["cps"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/uan/XNAME/workload/cpsmount_helper": spire_methods["cps"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/uan/XNAME/workload/dvs-hmi": spire_methods["dvs"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/uan/XNAME/workload/dvs-map": spire_methods["dvs"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/uan/XNAME/workload/heartbeat": spire_methods["heartbeat"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/uan/XNAME/workload/orca": spire_methods["dvs"],
}

{{- else }}
# List of endpoints we accept based on audience.
# From https://connect.us.cray.com/confluence/display/SKERN/Shasta+Compute+SPIRE+Security
# This is an initial set, not yet expected to be complete.
sub_match = {
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/compute/workload/bos-state-reporter": allowed_methods["system-compute"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/uan/workload/bos-state-reporter": allowed_methods["system-compute"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/ncn/workload/bos-state-reporter": allowed_methods["system-compute"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/compute/workload/cfs-state-reporter": allowed_methods["system-compute"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/storage/workload/cfs-state-reporter": allowed_methods["system-compute"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/ncn/workload/cfs-state-reporter": allowed_methods["system-compute"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/compute/workload/ckdump": allowed_methods["ckdump"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/uan/workload/ckdump": allowed_methods["ckdump"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/compute/workload/ckdump_helper": allowed_methods["ckdump"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/uan/workload/ckdump_helper": allowed_methods["ckdump"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/compute/workload/cpsmount": allowed_methods["system-compute"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/ncn/workload/cpsmount": allowed_methods["system-compute"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/compute/workload/cpsmount_helper": allowed_methods["system-compute"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/ncn/workload/cpsmount_helper": allowed_methods["system-compute"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/compute/workload/dvs-hmi": allowed_methods["system-compute"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/ncn/workload/dvs-hmi": allowed_methods["system-compute"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/compute/workload/dvs-map": allowed_methods["system-compute"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/ncn/workload/dvs-map": allowed_methods["system-compute"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/compute/workload/orca": allowed_methods["system-compute"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/ncn/workload/orca": allowed_methods["system-compute"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/compute/workload/wlm": allowed_methods["wlm"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/compute/workload/heartbeat": allowed_methods["system-compute"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/ncn/workload/heartbeat": allowed_methods["system-compute"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/storage/workload/heartbeat": allowed_methods["system-compute"],
    "spiffe://{{ .Values.jwtValidation.spire.trustDomain }}/uan/workload/heartbeat": allowed_methods["system-compute"],
}
{{- end }}
{{ end }}
