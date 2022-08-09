{{- /*
Copyright 2022 Hewlett Packard Enterprise Development LP
*/ -}}
{{ define "ingressgateway-hmn.policy" }}

# Istio Ingress HMN OPA Policy
package istio.authz

import input.attributes.request.http as http_request

# Default return a 403 unless any of the allows are true
default allow = {
  "allowed": false,
  "headers": {"x-ext-auth-allow": "no"},
  "body": "Unauthorized Request",
  "http_status": 403
}

# Whitelist traffic to HMS hmcollector
allow {
    http_request.headers["x-envoy-decorator-operation"] = "cray-hms-hmcollector.services.svc.cluster.local:80/*"
}

# The path being requested from the user. When the envoy filter is configured for
# SIDECAR_INBOUND this is: http_request.headers["x-envoy-original-path"].
# When configured for GATEWAY this is http_request.path
original_path = o_path {
    o_path := http_request.path
}

# Whitelist Keycloak, since those services enable users to login and obtain JWTs.
allow { startswith(original_path, "/keycloak") }

allow {
    roles_for_user[r]
    required_roles[r]
}

# Check if there is an authorization header and split the type from token
found_auth = {"type": a_type, "token": a_token} {
    [a_type, a_token] := split(http_request.headers.authorization, " ")
}

# If the auth type is bearer, decode the JWT
parsed_kc_token = {"payload": payload} {
    found_auth.type == "Bearer"
    response := http.send({"method": "get", "url": "{{ .Values.jwtValidation.keycloak.jwksUri }}", "cache": true, "tls_ca_cert_file": "/jwtValidationFetchTls/certificate_authority.crt"})
    [_, _, payload] := io.jwt.decode_verify(found_auth.token, {"cert": response.raw_body, "aud": "shasta"})

    # Verify that the issuer is as expected.
    allowed_issuers := [
{{- range $key, $value := index .Values "ingresses" "ingressgateway-hmn" "issuers" }}
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

# Our list of endpoints we accept based on roles.
role_perms = {
    "admin": allowed_methods["fabric"],
}

allowed_methods := {
  "fabric": [
      # Fabric Manager API access
      {"method": "DELETE", "path": `^/apis/fabric-manager/.*$`},
      {"method": "GET", "path": `^/apis/fabric-manager/.*$`},
      {"method": "HEAD", "path": `^/apis/fabric-manager/.*$`},
      {"method": "PATCH", "path": `^/apis/fabric-manager/.*$`},
      {"method": "POST", "path": `^/apis/fabric-manager/.*$`},
      {"method": "PUT", "path": `^/apis/fabric-manager/.*$`},
  ],
}

{{ end }}
