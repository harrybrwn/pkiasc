package main

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

func Test(t *testing.T) {
	expr, diags := hclsyntax.ParseExpression(
		[]byte(`[1,2,3,4,5]`),
		"",
		hcl.Pos{Byte: 0, Line: 1, Column: 1},
	)
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	fmt.Printf("%#v\n", expr)
	v, diags := expr.Value(nil)
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	for _, v := range v.AsValueSlice() {
		fmt.Println(v.AsBigFloat())
	}
}

func TestConfigHCL(t *testing.T) {
	const filename = "./testdata/config.hcl"
	bytes, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var c config
	diags := ParseConfig(&c, filename, bytes, nil)
	if diags.HasErrors() {
		t.Fatal(diags)
	}

	// raw, err := json.MarshalIndent(c, "", "  ")
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// fmt.Printf("%s\n", raw)

	if len(c.Store) == 0 {
		t.Fatal("empty store setting")
	}
	if c.KeySize == 0 {
		t.Fatal("zero key size")
	}

	s := newStore(&c)
	defer os.RemoveAll(s.dir)
	err = s.init()
	if err != nil {
		t.Fatal(err)
	}
}

func TestConfig(t *testing.T) {
	var (
		c    config
		date = time.Date(2000, time.January, 1, 2, 4, 6, 8, time.UTC)
	)
	now = func() time.Time { return date }
	diags := ParseConfig(&c, "test.hcl", []byte(`
store = "./testdata/TestConfig"
keysize = 1024
certificate "ca" {
	ca            = true
	not_after     = timeafter("365d")
	serial_number = serial()
	subject {
		common_name = title("testing root CA")
		organization = upper("test org")
	}
	key_usage = [key_usage.digital_signatures, key_usage.cert_sign]
}
certificate "cert_1" {
	issuer        = certificate.ca.id
	serial_number = serial()
	not_after     = timeafter("1y4mo")
	subject {
		common_name  = "jimmy.me"
		organization = certificate.ca.subject.organization
	}
	ext_key_usage = [ext_key_usage.server_auth]
	dns = ["jimmy.me", "*.jimmy.me"]
}
`), nil)
	if diags.HasErrors() {
		t.Fatal(diags)
	}

	if c.Store != "./testdata/TestConfig" {
		t.Fatal("wrong store path")
	}
	if c.KeySize != 1024 {
		t.Fatal("wrong key size")
	}
	if len(c.Certificates) != 2 {
		t.Fatal("wrong number of certificates")
	}
	if !c.Certificates[0].CA {
		t.Error("expected first one to be a CA ")
	}
	if c.Certificates[0].Subject.CommonName != "Testing Root CA" {
		t.Fatal("wrong common name")
	}
	if c.Certificates[1].subject().CommonName != "jimmy.me" {
		t.Fatal("wrong common name")
	}
	if c.Certificates[0].NotAfter != date.Add(time.Hour*24*365).Format(time.RFC3339Nano) {
		t.Fatal("wrong 'not_after' date")
	}
	if c.Certificates[1].NotAfter != date.Add((time.Hour*24*365)+(time.Hour*24*30*4)).Format(time.RFC3339Nano) {
		t.Fatal("wrong 'not_after' date")
	}
	if c.Certificates[1].IssuerID != c.Certificates[0].ID {
		t.Fatal("wrong issuer id")
	}
	if c.Certificates[0].Subject.Organization != "TEST ORG" {
		t.Fatal("wrong org name")
	}
	if c.Certificates[1].Subject.Organization != c.Certificates[0].Subject.Organization {
		t.Fatal("wrong org name")
	}
}

func TestStore(t *testing.T) {
}

func TestReadConfig(t *testing.T) {
}
