// Copyright 2021 Hewlett Packard Enterprise Development LP

package main

import (
  "encoding/base64"
  "encoding/json"
  "flag"
  "fmt"
  "html/template"
  "io/ioutil"
  "log"
  "math/rand"
  "net/http"
  "net/http/httptest"
  "os"
  "os/exec"
  "time"

  "github.com/Masterminds/sprig"
  "github.com/dgrijalva/jwt-go"
)

type tokenCreator struct {
  key []byte
}

type createTokenArgs struct {
  role   string
  issuer string
  aud    string
  sub    string
  typ    string
}

func (t tokenCreator) create(args createTokenArgs) (string, error) {
  var err error
  atClaims := jwt.MapClaims{}
  atClaims["iss"] = args.issuer
  atClaims["exp"] = time.Now().Add(time.Minute * 15).Unix()
  atClaims["aud"] = []string{args.aud}
  if args.role != "" {
    atClaims["resource_access"] = map[string]interface{}{
      "shasta": map[string]interface{}{
        "roles": []string{args.role},
      },
    }
  }
  if args.sub != "" {
    atClaims["sub"] = args.sub
  }
  if args.typ != "" {
    atClaims["typ"] = args.typ
  }
  at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
  token, err := at.SignedString(t.key)
  if err != nil {
    return "", err
  }
  return token, nil
}

func main() {
  flag.Parse()

  policyTemplateFilename := flag.Arg(0)
  testTemplateFilename := flag.Arg(1)
  policyTemplateName := flag.Arg(2)

  randomKey := make([]byte, 32)
  rand.Read(randomKey)

  tc := tokenCreator{key: randomKey}

  randomKeyB64 := base64.RawURLEncoding.EncodeToString(randomKey)

  jwksResponseData := map[string]interface{}{
    "keys": []interface{}{
      map[string]interface{}{
        "kid": "MoeoCPOcAKjkbMy7k-IhGMtjvqehZqRTqevioCtoaNM",
        "kty": "oct",
        "k":   randomKeyB64,
        "alg": "HS256",
      },
    },
  }

  jwksResponse, err := json.Marshal(jwksResponseData)
  if err != nil {
    log.Fatal(err)
  }

  ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    fmt.Println("JWKS FETCHED!")
    fmt.Fprintln(w, string(jwksResponse))
  }))
  defer ts.Close()

  keycloakIssuer := "http://keycloak1"
  spireIssuer := "http://spire.local/shasta/vshastaio"
  shastaAud := "shasta"
  systemComputeAud := "system-compute"
  var spireSub string

  args := createTokenArgs{
    role: "admin", issuer: keycloakIssuer, aud: shastaAud, typ: "Bearer"}
  adminToken, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println("admin token:", adminToken)

  args = createTokenArgs{role: "user", issuer: keycloakIssuer, aud: shastaAud, typ: "Bearer"}
  userToken, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println("user token:", userToken)

  args = createTokenArgs{role: "admin", issuer: keycloakIssuer, aud: shastaAud, typ: "Invalid"}
  invalidTypAdminToken, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println("Invalid typ admin token:", invalidTypAdminToken)

  args = createTokenArgs{
    role: "system-pxe", issuer: keycloakIssuer, aud: shastaAud, typ: "Bearer"}
  pxeToken, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println("pxe token:", pxeToken)

  args = createTokenArgs{
    role: "system-compute", issuer: keycloakIssuer, aud: shastaAud, typ: "Bearer"}
  computeToken, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println("compute token:", computeToken)

  args = createTokenArgs{role: "wlm", issuer: keycloakIssuer, aud: shastaAud, typ: "Bearer"}
  wlmToken, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println("wlm token:", wlmToken)

  spireSub = "spiffe://shasta/invalid"
  args = createTokenArgs{
    issuer: spireIssuer, aud: systemComputeAud, sub: spireSub}
  spireInvalidSub, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(spireSub, ":", spireInvalidSub)

  spireSub = "spiffe://shasta/ncn/ncnw001/workload/cfs-state-reporter"
  args = createTokenArgs{
    issuer: spireIssuer, aud: systemComputeAud, sub: spireSub}
  spireNcnCfsStateReporter, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(spireSub, ":", spireNcnCfsStateReporter)

  spireSub = "spiffe://shasta/ncn/ncnw001/workload/ckdump"
  args = createTokenArgs{
    issuer: spireIssuer, aud: systemComputeAud, sub: spireSub}
  spireNcnCkdump, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(spireSub, ":", spireNcnCkdump)

  spireSub = "spiffe://shasta/ncn/ncnw001/workload/ckdump_helper"
  args = createTokenArgs{
    issuer: spireIssuer, aud: systemComputeAud, sub: spireSub}
  spireNcnCkdumpHelper, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(spireSub, ":", spireNcnCkdumpHelper)

  spireSub = "spiffe://shasta/ncn/ncnw001/workload/cpsmount"
  args = createTokenArgs{
    issuer: spireIssuer, aud: systemComputeAud, sub: spireSub}
  spireNcnCpsmount, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(spireSub, ":", spireNcnCpsmount)

  spireSub = "spiffe://shasta/ncn/ncnw001/workload/cpsmount_helper"
  args = createTokenArgs{
    issuer: spireIssuer, aud: systemComputeAud, sub: spireSub}
  spireNcnCpsmountHelper, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(spireSub, ":", spireNcnCpsmountHelper)

  spireSub = "spiffe://shasta/ncn/ncnw001/workload/dvs-hmi"
  args = createTokenArgs{
    issuer: spireIssuer, aud: systemComputeAud, sub: spireSub}
  spireNcnDvsHmi, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(spireSub, ":", spireNcnDvsHmi)

  spireSub = "spiffe://shasta/ncn/ncnw001/workload/dvs-map"
  args = createTokenArgs{
    issuer: spireIssuer, aud: systemComputeAud, sub: spireSub}
  spireNcnDvsMap, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(spireSub, ":", spireNcnDvsMap)

  spireSub = "spiffe://shasta/ncn/ncnw001/workload/heartbeat"
  args = createTokenArgs{
    issuer: spireIssuer, aud: systemComputeAud, sub: spireSub}
  spireNcnHeartbeat, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(spireSub, ":", spireNcnHeartbeat)

  spireSub = "spiffe://shasta/ncn/ncnw001/workload/orca"
  args = createTokenArgs{
    issuer: spireIssuer, aud: systemComputeAud, sub: spireSub}
  spireNcnOrca, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(spireSub, ":", spireNcnOrca)

  spireSub = "spiffe://shasta/compute/x1/workload/cfs-state-reporter"
  args = createTokenArgs{
    issuer: spireIssuer, aud: systemComputeAud, sub: spireSub}
  spireComputeCfsStateReporter, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(spireSub, ":", spireComputeCfsStateReporter)

  spireSub = "spiffe://shasta/compute/x1/workload/ckdump"
  args = createTokenArgs{
    issuer: spireIssuer, aud: systemComputeAud, sub: spireSub}
  spireComputeCkdump, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(spireSub, ":", spireComputeCkdump)

  spireSub = "spiffe://shasta/compute/x1/workload/ckdump_helper"
  args = createTokenArgs{
    issuer: spireIssuer, aud: systemComputeAud, sub: spireSub}
  spireComputeCkdumpHelper, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(spireSub, ":", spireComputeCkdumpHelper)

  spireSub = "spiffe://shasta/compute/x1/workload/cpsmount"
  args = createTokenArgs{
    issuer: spireIssuer, aud: systemComputeAud, sub: spireSub}
  spireComputeCpsmount, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(spireSub, ":", spireComputeCpsmount)

  spireSub = "spiffe://shasta/compute/x1/workload/cpsmount_helper"
  args = createTokenArgs{
    issuer: spireIssuer, aud: systemComputeAud, sub: spireSub}
  spireComputeCpsmountHelper, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(spireSub, ":", spireComputeCpsmountHelper)

  spireSub = "spiffe://shasta/compute/x1/workload/dvs-hmi"
  args = createTokenArgs{
    issuer: spireIssuer, aud: systemComputeAud, sub: spireSub}
  spireComputeDvsHmi, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(spireSub, ":", spireComputeDvsHmi)

  spireSub = "spiffe://shasta/compute/x1/workload/dvs-map"
  args = createTokenArgs{
    issuer: spireIssuer, aud: systemComputeAud, sub: spireSub}
  spireComputeDvsMap, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(spireSub, ":", spireComputeDvsMap)

  spireSub = "spiffe://shasta/compute/x1/workload/heartbeat"
  args = createTokenArgs{
    issuer: spireIssuer, aud: systemComputeAud, sub: spireSub}
  spireComputeHeartbeat, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(spireSub, ":", spireComputeHeartbeat)

  spireSub = "spiffe://shasta/compute/x1/workload/orca"
  args = createTokenArgs{
    issuer: spireIssuer, aud: systemComputeAud, sub: spireSub}
  spireComputeOrca, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(spireSub, ":", spireComputeOrca)

  spireSub = "spiffe://shasta/compute/x1/workload/wlm"
  args = createTokenArgs{
    issuer: spireIssuer, aud: systemComputeAud, sub: spireSub}
  spireComputeWlm, err := tc.create(args)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(spireSub, ":", spireComputeWlm)

  // Reading in the policy template file and generating policy file.

  dat, err := ioutil.ReadFile(policyTemplateFilename)
  if err != nil {
    log.Fatal(err)
  }
  // fmt.Println("Read the template file %v", string(dat))

  tpl := template.Must(
    template.New("base").Funcs(sprig.FuncMap()).Parse(string(dat)))

  values := map[string]interface{}{
    "Values": map[string]interface{}{
      "opa": map[string]interface{}{
        "xnamePolicy": map[string]interface{}{
          "enabled":   "True",
          "bos":       "True",
          "cfs":       "True",
          "dvs":       "True",
          "heartbeat": "True",
        },
        "requireHeartbeatToken": "True",
      },
      "ingresses": map[string]interface{}{
        "ingressgateway": map[string]interface{}{
            "issuers": []string{keycloakIssuer},
          },
        "ingressgateway-customer-admin": map[string]interface{}{
            "issuers": []string{keycloakIssuer},
          },
        "ingressgateway-customer-user": map[string]interface{}{
            "issuers": []string{keycloakIssuer},
          },
        },
      "jwtValidation": map[string]interface{}{
        "keycloak": map[string]interface{}{
          "jwksUri": ts.URL,
        },
        "spire": map[string]interface{}{
          "jwksUri":     ts.URL,
          "issuers":     []string{spireIssuer},
          "trustDomain": "shasta",
        },
      },
    },
  }

  f, err := os.Create("policy.rego")
  if err != nil {
    log.Fatal(err)
  }

  defer f.Close()

  fmt.Println("Rendering policy template to 'policy.rego'")
  err = tpl.ExecuteTemplate(f, policyTemplateName, values)
  if err != nil {
    log.Fatal(err)
  }

  f.Close()

  fmt.Println("Rendered policy template:")
  fmt.Println("*****")

  dat, err = ioutil.ReadFile("policy.rego")
  if err != nil {
    log.Fatal(err)
  }
  fmt.Printf("%s", string(dat))

  fmt.Println("*****")

  // Reading in the test template file and creating test file.
  dat, err = ioutil.ReadFile(testTemplateFilename)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println("Read the test template file %v", string(dat))

  tpl = template.Must(
    template.New("base").Funcs(sprig.FuncMap()).Parse(string(dat)))

  values = map[string]interface{}{
    "userToken":            userToken,
    "adminToken":           adminToken,
    "invalidTypAdminToken": invalidTypAdminToken,
    "pxeToken":             pxeToken,
    "computeToken":         computeToken,
    "wlmToken":             wlmToken,
    "spire": map[string]interface{}{
      "invalidSub": spireInvalidSub,
      "ncn": map[string]interface{}{
        "cfs_state_reporter": spireNcnCfsStateReporter,
        "ckdump":             spireNcnCkdump,
        "ckdump_helper":      spireNcnCkdumpHelper,
        "cpsmount":           spireNcnCpsmount,
        "cpsmount_helper":    spireNcnCpsmountHelper,
        "dvs_hmi":            spireNcnDvsHmi,
        "dvs_map":            spireNcnDvsMap,
        "heartbeat":          spireNcnHeartbeat,
        "orca":               spireNcnOrca,
      },
      "compute": map[string]interface{}{
        "cfs_state_reporter": spireComputeCfsStateReporter,
        "ckdump":             spireComputeCkdump,
        "ckdump_helper":      spireComputeCkdumpHelper,
        "cpsmount":           spireComputeCpsmount,
        "cpsmount_helper":    spireComputeCpsmountHelper,
        "dvs_hmi":            spireComputeDvsHmi,
        "dvs_map":            spireComputeDvsMap,
        "heartbeat":          spireComputeHeartbeat,
        "orca":               spireComputeOrca,
        "wlm":                spireComputeWlm,
      },
    },
  }

  f, err = os.Create("test.rego")
  if err != nil {
    log.Fatal(err)
  }

  defer f.Close()

  fmt.Println("Rendering test template to 'test.rego'")
  err = tpl.Execute(f, values)
  if err != nil {
    log.Fatal(err)
  }

  f.Close()

  fmt.Println("Rendered test template:")
  fmt.Println("*****")

  dat, err = ioutil.ReadFile("test.rego")
  if err != nil {
    log.Fatal(err)
  }
  fmt.Printf("%s", string(dat))

  fmt.Println("*****")

  fmt.Printf("GET %s\n", ts.URL)
  res, err := http.Get(ts.URL)
  if err != nil {
    log.Fatal(err)
  }
  greeting, err := ioutil.ReadAll(res.Body)
  res.Body.Close()
  if err != nil {
    log.Fatal(err)
  }

  fmt.Printf("%s", greeting)
  fmt.Println("*****")

  fmt.Println("Executing ./opa_envoy_linux_amd64 test ./policy.rego ./test.rego -v")

  cmd := exec.Command("./opa_envoy_linux_amd64", "test", "./policy.rego", "./test.rego", "-v")
  cmd.Stdout = os.Stdout
  cmd.Stderr = os.Stderr

  err = cmd.Run()
  if err != nil {
    log.Fatal(err)
  }
}
