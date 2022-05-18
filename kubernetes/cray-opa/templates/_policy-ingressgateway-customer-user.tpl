{{- /*
Copyright 2021 Hewlett Packard Enterprise Development LP
*/ -}}
{{ define "ingressgateway-customer-user.policy" }}

# Istio Ingress Customer User Gateway OPA Policy
package istio.authz

import input.attributes.request.http as http_request
import input.attributes.source.address as source_address

# Default return a 403 unless any of the allows are true
default allow = {
  "allowed": false,
  "headers": {"x-ext-auth-allow": "no"},
  "body": "Unauthorized Request",
  "http_status": 403
}

# Whitelist traffic to HMS hmcollector from the HMN and pod subnets
allow {
    # Limit scope to hmcollector to prevent unauthenticated access to other
    # management services.
    http_request.headers["x-envoy-decorator-operation"] = "cray-hms-hmcollector.services.svc.cluster.local:80/*"
    any([
        # HMN subnet (River)
        net.cidr_contains("10.254.0.0/17", source_address.Address.SocketAddress.address),
        # HMN subnet (Mountain)
        net.cidr_contains("10.100.106.0/23", source_address.Address.SocketAddress.address),
        # pod subnet
        net.cidr_contains("10.32.0.0/12", source_address.Address.SocketAddress.address),
    ])
}

# Whitelist traffic to the Neuxs web UI since it uses Keycloak for authentication.
allow {
    http_request.headers["x-envoy-decorator-operation"] = "nexus.nexus.svc.cluster.local:80/*"
}

# The path being requested from the user. When the envoy filter is configured for
# SIDECAR_INBOUND this is: http_request.headers["x-envoy-original-path"].
# When configured for GATEWAY this is http_request.path
original_path = o_path {
    o_path := http_request.path
}

# Whitelist Keycloak, since those services enable users to login and obtain
# JWTs. vcs are also enabled here. Legacy services to be migrated or removed:
#
#     * VCS/Gitea
#
allow {
    any([
        startswith(original_path, "/keycloak"),
        startswith(original_path, "/vcs"),
    ])
}

# Allow cloud-init endpoints, as we do validation based on incoming IP.
# In the future, these requests will come in via the TOR switches and ideally
# not through the 'front door'.   This is an expansion to BSS.
allow {
    any([
        startswith(original_path, "/meta-data"),
        startswith(original_path, "/user-data"),
        startswith(original_path, "/phone-home"),
    ])
}

# Whitelist Nexus repository pods. Nexus uses it's own RBAC so open
# all commands. Keycloak Gatekeeper is used to pass the tokens through
allow {
    any([
        startswith(original_path, "/repository"),
        startswith(original_path, "/v2"),
        startswith(original_path, "/service/rest"),
    ])
}

# Whitelist Capsules UI. The Capsules UI starts at a login page which validates user access by retrieving a valid
# token from keycloak with the provided credentials.
allow {
    any([
        startswith(original_path, "/capsules/")
    ])
}

# This actually checks that the JWT token passed in
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
    [valid, header, payload] := io.jwt.decode_verify(found_auth.token, {"cert": response.raw_body, "aud": "shasta"})

    # Verify that the issuer is as expected.
    allowed_issuers := [
{{- range $key, $value := index .Values "ingresses" "ingressgateway-customer-user" "issuers" }}
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
      # PALS - application launch
      {"method": "GET", "path": `^/apis/pals/.*$`},
      {"method": "HEAD", "path": `^/apis/pals/.*$`},
      {"method": "POST", "path": `^/apis/pals/.*$`},
      {"method": "DELETE", "path": `^/apis/pals/.*$`},

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
  ],
  "ckdump": [
      {"method": "GET",  "path": `^/apis/v2/nmd/.*$`},
      {"method": "HEAD",  "path": `^/apis/v2/nmd/.*$`},
      {"method": "POST",  "path": `^/apis/v2/nmd/.*$`},
      {"method": "PUT",  "path": `^/apis/v2/nmd/.*$`},
  ],
}

# Our list of endpoints we accept based on roles.
role_perms = {
    "user": allowed_methods["user"],
    "wlm": allowed_methods["wlm"],
    "ckdump": allowed_methods["ckdump"],
}


{{ end }}
