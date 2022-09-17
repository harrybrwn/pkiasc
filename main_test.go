package main

import (
	"os"
	"testing"
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

func TestStore(t *testing.T) {
}

func TestReadConfig(t *testing.T) {
}
