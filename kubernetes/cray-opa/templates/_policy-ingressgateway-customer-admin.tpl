{{- /*
Copyright 2021-2022 Hewlett Packard Enterprise Development LP
*/ -}}
{{ define "ingressgateway-customer-admin.policy" }}

# Istio Ingress Customer Admin Gateway OPA Policy
package istio.authz
import future.keywords.in
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

# Allow all access to Keycloak, also apply mitigations
allow
{
    startswith(original_path, "/keycloak")
    # Mitigate CVE-2020-10770
    not re_match(`^/keycloak/realms/[a-zA-Z0-9]+/protocol/openid-connect/.*request_uri=.*$`, original_path)
}

# Allow all access to Gitea/VCS
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

# This actually checks the JWT token passed in
# has access to the endpoint requested
allow {
    roles_for_user[r]
    required_roles[r]
}

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
{{- range $key, $value := index .Values "ingresses" "ingressgateway-customer-admin" "issuers" }}
      "{{ $value }}",
{{- end }}
    ]
    allowed_issuers[_] = payload.iss
}

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
  "admin": [
      {"method": "GET",  "path": `.*`},
      {"method": "PUT",  "path": `.*`},
      {"method": "POST",  "path": `.*`},
      {"method": "DELETE",  "path": `.*`},
      {"method": "PATCH",  "path": `.*`},
      {"method": "HEAD",  "path": `.*`},
  ],
  "ckdump": [
      {"method": "GET",  "path": `^/apis/v2/nmd/.*$`},
      {"method": "HEAD",  "path": `^/apis/v2/nmd/.*$`},
      {"method": "POST",  "path": `^/apis/v2/nmd/.*$`},
      {"method": "PUT",  "path": `^/apis/v2/nmd/.*$`},
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
    "wlm": allowed_methods["wlm"],
    "admin": allowed_methods["admin"],
    "ckdump": allowed_methods["ckdump"],
    "monitor-ro": allowed_methods["monitor-ro"],
}

{{ end }}
