package main

import (
	"os"
	"testing"
	"time"
)

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

	if len(c.Store) == 0 {
		t.Fatal("empty store setting")
	}
	if c.KeySize == 0 {
		t.Fatal("zero key size")
	}

	s := newStore(&c)
	defer os.RemoveAll(s.dir)
	err = s.init(false)
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
	defer func() { now = time.Now }()
	diags := ParseConfig(&c, "test.hcl", []byte(`
store = "./testdata/TestConfig"
keysize = 1024
var "not_before" {}
certificate "ca" {
	ca            = true
	not_after     = timeafter("365d")
	serial_number = serial()
	not_before    = timeafter(var.not_before)
	subject {
		common_name = title("testing root CA")
		organization = upper("test org")
	}
	key_usage = [key_usage.digital_signatures, key_usage.cert_sign]
	public_key_algorithm = "rsa"
}
certificate "cert_1" {
	issuer        = certificate.ca.id
	serial_number = serial()
	not_after     = timeafter("1y4mo")
	not_before    = timeafter(var.not_before)
	subject {
		common_name  = "jimmy.me"
		organization = certificate.ca.subject.organization
	}
	ext_key_usage = [ext_key_usage.server_auth]
	dns = ["jimmy.me", "*.jimmy.me"]
	signature_algorithm = "sha256-rsa"
}
`), []string{"not_before=1mo5m35ms"})
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

func Test(t *testing.T) {
}
