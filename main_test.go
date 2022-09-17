package main

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"gopkg.in/yaml.v2"
)

func TestConfigHCL(t *testing.T) {
	const filename = "./testdata/config.hcl"
	bytes, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var c config
	diags := ParseConfig(&c, bytes, "config.hcl")
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%s\n", raw)

	s := newStore(&c)
	os.RemoveAll(s.dir)
	err = s.init()
	if err != nil {
		t.Fatal(err)
	}
}

func TestStore(t *testing.T) {
	c := testConfig()
	s := newStore(c)
	os.RemoveAll(s.dir)
	err := s.validate()
	if err != nil {
		t.Fatal(err)
	}
	err = s.init()
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadConfig(t *testing.T) {
	c := testConfig()
	if c.Store == "" {
		t.Fatal("store setting should not be empty")
	}
	if len(c.Certificates) == 0 {
		t.Fatal("config should have certificates")
	}
}

func testConfig() *config {
	var c config
	f, err := os.Open("./testdata/config.yml")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	err = yaml.NewDecoder(f).Decode(&c)
	if err != nil {
		panic(err)
	}
	return &c
}
