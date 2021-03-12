// Copyright 2021 Hewlett Packard Enterprise Development LP

package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/Masterminds/sprig"
	"github.com/dgrijalva/jwt-go"
	"html/template"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"time"
)

type tokenCreator struct {
	key []byte
}

type createTokenArgs struct {
	role   string
	issuer string
	aud    string
	sub    string
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
	spireIssuer := "http://spire1"
	shastaAud := "shasta"
	systemComputeAud := "system-compute"
	spiffeSub := "spiffe://vshasta.io/x123"

	args := createTokenArgs{
		role: "admin", issuer: keycloakIssuer, aud: shastaAud}
	adminToken, err := tc.create(args)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("admin token:", adminToken)

	args = createTokenArgs{role: "user", issuer: keycloakIssuer, aud: shastaAud}
	userToken, err := tc.create(args)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("user token:", userToken)

	args = createTokenArgs{
		role: "system-pxe", issuer: keycloakIssuer, aud: shastaAud}
	pxeToken, err := tc.create(args)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("pxe token:", pxeToken)

	args = createTokenArgs{
		role: "system-compute", issuer: keycloakIssuer, aud: shastaAud}
	computeToken, err := tc.create(args)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("compute token:", computeToken)

	args = createTokenArgs{role: "wlm", issuer: keycloakIssuer, aud: shastaAud}
	wlmToken, err := tc.create(args)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("wlm token:", wlmToken)

	args = createTokenArgs{
		role: "invalid-role", issuer: keycloakIssuer, aud: shastaAud}
	invalidToken, err := tc.create(args)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("invalid token:", invalidToken)

	args = createTokenArgs{
		issuer: spireIssuer, aud: systemComputeAud, sub: spiffeSub}
	spireToken, err := tc.create(args)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("spire token:", spireToken)

	args = createTokenArgs{
		issuer: spireIssuer, aud: "invalid", sub: spiffeSub}
	spireInvalidAudToken, err := tc.create(args)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("invalid spire token (unexpected aud):", spireInvalidAudToken)

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
			"jwtValidation": map[string]interface{}{
				"keycloak": map[string]interface{}{
					"jwksUri": ts.URL,
					"issuers": []string{keycloakIssuer},
				},
				"spire": map[string]interface{}{
					"jwksUri": ts.URL,
					"issuers": []string{spireIssuer},
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
	err = tpl.ExecuteTemplate(f, "cray-opa.policy", values)
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
		"pxeToken":             pxeToken,
		"computeToken":         computeToken,
		"wlmToken":             wlmToken,
		"invalidToken":         invalidToken,
		"spireToken":           spireToken,
		"spireInvalidAudToken": spireInvalidAudToken,
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
