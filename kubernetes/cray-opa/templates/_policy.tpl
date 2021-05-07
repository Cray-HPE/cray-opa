{{- /*
Copyright 2020 Hewlett Packard Enterprise Development LP
*/ -}}
{{ define "cray-opa.policy" }}

# Istio Ingress Gateway OPA Policy
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

# The path being requested from the user. When the envoy filter is configured for
# SIDECAR_INBOUND this is: http_request.headers["x-envoy-original-path"].
# When configured for GATEWAY this is http_request.path
original_path = o_path {
    o_path := http_request.path
}

# Whitelist Keycloak and tokens service, since those services enable users to
# login and obtain JWTs. Legacy services to be migrated or removed:
#
#     * VCS/Gitea
#
allow {
    any([
        startswith(original_path, "/keycloak"),
        startswith(original_path, "/apis/tokens"),
        startswith(original_path, "/vcs"),
        startswith(original_path, "/spire-jwks-"),
        startswith(original_path, "/spire-bundle"),
    ])
}

# Allow cloud-init endpoints, as we do validation based on incoming IP.
# In the future, these requests will come in via the TOR switches and ideally
# not through the 'front door'
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

# Allow heartbeats without requiring a spire token
allow {
    any([
        startswith(original_path, "/apis/hbtd/")
    ])
}

# This actually checks the the JWT token passed in
# has access to the endpoint requested
allow {
    roles_for_user[r]
    required_roles[r]
}

# Validate claims for SPIRE issued JWT tokens
allow {
    # Parse subject and audience
    s := parsed_spire_token.payload.sub
    a := parsed_spire_token.payload.aud

    # Test subject is valid
    startswith(s, "spiffe://")

    # Test audience is valid and matches destination
    # NOTE: Only the first audience is used
    perm := audience_match[a[0]][_]
    perm.method = http_request.method
    re_match(perm.path, original_path)
}

# Check if there is an authorization header and split the type from token
found_auth = {"type": a_type, "token": a_token} {
    [a_type, a_token] := split(http_request.headers.authorization, " ")
}

# If the auth type is bearer, decode the JWT
parsed_kc_token = {"payload": payload} {
    found_auth.type == "Bearer"
    response := http.send({"method": "get", "url": "{{ .Values.jwtValidation.keycloak.jwksUri }}", "cache": true, "tls_ca_cert_file": "/jwtValidationFetchTls/certificate_authority.crt"})
    [valid, header, payload] := io.jwt.decode_verify(found_auth.token, {"cert": response.raw_body, "aud": "shasta"})

    # Verify that the issuer is as expected.
    allowed_issuers := [
{{- range $key, $value := .Values.jwtValidation.keycloak.issuers }}
      {{ $value | quote }},
{{- end }}
    ]
    allowed_issuers[_] = payload.iss
}

# If the auth type is bearer, decode the JWT
parsed_spire_token = {"payload": payload} {
    found_auth.type == "Bearer"
    response := http.send({"method": "get", "url": "{{ .Values.jwtValidation.spire.jwksUri }}", "cache": true, "tls_ca_cert_file": "/jwtValidationFetchTls/certificate_authority.crt"})
    [valid, header, payload] := io.jwt.decode_verify(found_auth.token, {"cert": response.raw_body, "aud": "system-compute"})

    # Verify that the issuer is as expected.
    allowed_issuers := [
{{- range $key, $value := .Values.jwtValidation.spire.issuers }}
      {{ $value | quote }},
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
  ],
  "system-pxe": [
      {"method": "GET",  "path": `^/apis/bss/.*$`},
      {"method": "HEAD",  "path": `^/apis/bss/.*$`},
      {"method": "POST",  "path": `^/apis/bss/.*$`},
  ],
  "system-compute": [
    {"method": "GET",  "path": `^/apis/cfs/.*$`},
    {"method": "HEAD",  "path": `^/apis/cfs/.*$`},
    {"method": "PATCH",  "path": `^/apis/cfs/.*$`},

    {"method": "GET",  "path": `^/apis/v2/cps/.*$`},
    {"method": "HEAD",  "path": `^/apis/v2/cps/.*$`},
    {"method": "POST",  "path": `^/apis/v2/cps/.*$`},

    {"method": "GET",  "path": `^/apis/v2/nmd/.*$`},
    {"method": "HEAD",  "path": `^/apis/v2/nmd/.*$`},
    {"method": "POST",  "path": `^/apis/v2/nmd/.*$`},
    {"method": "PUT",  "path": `^/apis/v2/nmd/.*$`},

    {"method": "GET",  "path": `^/apis/smd/.*$`},
    {"method": "HEAD",  "path": `^/apis/smd/.*$`},
    {"method": "PATCH",  "path": `^/apis/smd/hsm/v1/State/Components/BulkSoftwareStatus$`},

    {"method": "GET",  "path": `^/apis/hmnfd/.*$`},
    {"method": "HEAD",  "path": `^/apis/hmnfd/.*$`},
    {"method": "PATCH",  "path": `^/apis/hmnfd/.*$`},
    {"method": "POST",  "path": `^/apis/hmnfd/.*$`},
    {"method": "DELETE",  "path": `^/apis/hmnfd/.*$`},
  ],
  "wlm": [
      # PALS - application launch
      {"method": "GET", "path": `^/apis/pals/.*$`},
      {"method": "HEAD", "path": `^/apis/pals/.*$`},
      {"method": "POST", "path": `^/apis/pals/.*$`},
      {"method": "DELETE", "path": `^/apis/pals/.*$`},
      # CAPMC - power capping
      {"method": "GET", "path": `^/apis/capmc/.*$`},
      {"method": "HEAD", "path": `^/apis/capmc/.*$`},
      {"method": "POST", "path": `^/apis/capmc/.*$`},
      # BOS - node boot
      {"method": "GET", "path": `^/apis/bos/.*$`},
      {"method": "HEAD", "path": `^/apis/bos/.*$`},
      {"method": "POST", "path": `^/apis/bos/.*$`},
      {"method": "PATCH", "path": `^/apis/bos/.*$`},
      {"method": "DELETE", "path": `^/apis/bos/.*$`},
      # SLS - hardware query
      {"method": "GET", "path": `^/apis/sls/.*$`},
      {"method": "HEAD", "path": `^/apis/sls/.*$`},
      # SMD - hardware state query
      {"method": "GET", "path": `^/apis/smd/.*$`},
      {"method": "HEAD", "path": `^/apis/smd/.*$`},
      # FC - VNI reservation
      {"method": "GET", "path": `^/apis/fc/.*$`},
      {"method": "HEAD", "path": `^/apis/fc/.*$`},
      {"method": "POST", "path": `^/apis/fc/.*$`},
      {"method": "PUT", "path": `^/apis/fc/.*$`},
      {"method": "DELETE", "path": `^/apis/fc/.*$`},
  ],
  "admin": [
      {"method": "GET",  "path": `.*`},
      {"method": "PUT",  "path": `.*`},
      {"method": "POST",  "path": `.*`},
      {"method": "DELETE",  "path": `.*`},
      {"method": "PATCH",  "path": `.*`},
      {"method": "HEAD",  "path": `.*`},
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
}

# List of endpoints we accept based on audience.
# From https://connect.us.cray.com/confluence/display/SKERN/Shasta+Compute+SPIRE+Security
# This is an initial set, not yet expected to be complete.
audience_match = {
  "system-compute": allowed_methods["system-compute"],
}

{{ end }}
