package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"hash"
	"strconv"
	"time"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"

	"gopkg.hrry.dev/pki/internal/times"
)

const timestampFormat = time.RFC3339Nano

var stdlibFunctions = map[string]function.Function{
	"abs":             stdlib.AbsoluteFunc,
	"add":             stdlib.AddFunc,
	"ceil":            stdlib.CeilFunc,
	"chomp":           stdlib.ChompFunc,
	"coalescelist":    stdlib.CoalesceListFunc,
	"compact":         stdlib.CompactFunc,
	"concat":          stdlib.ConcatFunc,
	"contains":        stdlib.ContainsFunc,
	"csvdecode":       stdlib.CSVDecodeFunc,
	"distinct":        stdlib.DistinctFunc,
	"element":         stdlib.ElementFunc,
	"chunklist":       stdlib.ChunklistFunc,
	"flatten":         stdlib.FlattenFunc,
	"floor":           stdlib.FloorFunc,
	"format":          stdlib.FormatFunc,
	"formatdate":      stdlib.FormatDateFunc,
	"formatlist":      stdlib.FormatListFunc,
	"indent":          stdlib.IndentFunc,
	"index":           stdlib.IndexFunc,
	"join":            stdlib.JoinFunc,
	"jsondecode":      stdlib.JSONDecodeFunc,
	"jsonencode":      stdlib.JSONEncodeFunc,
	"keys":            stdlib.KeysFunc,
	"log":             stdlib.LogFunc,
	"lower":           stdlib.LowerFunc,
	"max":             stdlib.MaxFunc,
	"merge":           stdlib.MergeFunc,
	"min":             stdlib.MinFunc,
	"parseint":        stdlib.ParseIntFunc,
	"pow":             stdlib.PowFunc,
	"quote":           quoteFunc,
	"range":           stdlib.RangeFunc,
	"regex":           stdlib.RegexFunc,
	"regexall":        stdlib.RegexAllFunc,
	"reverse":         stdlib.ReverseListFunc,
	"setintersection": stdlib.SetIntersectionFunc,
	"setproduct":      stdlib.SetProductFunc,
	"setsubtract":     stdlib.SetSubtractFunc,
	"setunion":        stdlib.SetUnionFunc,
	// TODO add a serial_strategy option that control how serial numbers are generated
	"serial":     SerialFunction(0x1000),
	"sha1":       makeStringHashFunction(sha1.New, hex.EncodeToString),
	"sha256":     makeStringHashFunction(sha256.New, hex.EncodeToString),
	"sha512":     makeStringHashFunction(sha512.New, hex.EncodeToString),
	"signum":     stdlib.SignumFunc,
	"slice":      stdlib.SliceFunc,
	"sort":       stdlib.SortFunc,
	"split":      stdlib.SplitFunc,
	"strrev":     stdlib.ReverseFunc,
	"substr":     stdlib.SubstrFunc,
	"timeadd":    stdlib.TimeAddFunc,
	"timeafter":  timeAfterFunc,
	"title":      stdlib.TitleFunc,
	"trim":       stdlib.TrimFunc,
	"trimprefix": stdlib.TrimPrefixFunc,
	"trimspace":  stdlib.TrimSpaceFunc,
	"trimsuffix": stdlib.TrimSuffixFunc,
	"upper":      stdlib.UpperFunc,
	"values":     stdlib.ValuesFunc,
	"zipmap":     stdlib.ZipmapFunc,
}

var (
	keyUsageConstants = map[string]cty.Value{
		"digital_signatures": intVal(x509.KeyUsageDigitalSignature),
		"content_commitment": intVal(x509.KeyUsageContentCommitment),
		"key_encipherment":   intVal(x509.KeyUsageKeyEncipherment),
		"data_encipherment":  intVal(x509.KeyUsageDataEncipherment),
		"key_agreement":      intVal(x509.KeyUsageKeyAgreement),
		"cert_sign":          intVal(x509.KeyUsageCertSign),
		"crl_sign":           intVal(x509.KeyUsageCRLSign),
		"encipher_only":      intVal(x509.KeyUsageEncipherOnly),
		"decipher_only":      intVal(x509.KeyUsageDecipherOnly),
	}
	extKeyUsageConstants = map[string]cty.Value{
		"any":                               intVal(x509.ExtKeyUsageAny),
		"server_auth":                       intVal(x509.ExtKeyUsageServerAuth),
		"client_auth":                       intVal(x509.ExtKeyUsageClientAuth),
		"code_signing":                      intVal(x509.ExtKeyUsageCodeSigning),
		"email_protection":                  intVal(x509.ExtKeyUsageEmailProtection),
		"ipsec_end_systemd":                 intVal(x509.ExtKeyUsageIPSECEndSystem),
		"ipsec_tunnel":                      intVal(x509.ExtKeyUsageIPSECTunnel),
		"ipsec_user":                        intVal(x509.ExtKeyUsageIPSECUser),
		"time_stamping":                     intVal(x509.ExtKeyUsageTimeStamping),
		"ocsp_signing":                      intVal(x509.ExtKeyUsageOCSPSigning),
		"microsoft_server_gated_crypto":     intVal(x509.ExtKeyUsageMicrosoftServerGatedCrypto),
		"netscape_server_gated_crypto":      intVal(x509.ExtKeyUsageNetscapeServerGatedCrypto),
		"microsoft_commercial_code_signing": intVal(x509.ExtKeyUsageMicrosoftCommercialCodeSigning),
		"microsoft_kernel_code_signing":     intVal(x509.ExtKeyUsageMicrosoftKernelCodeSigning),
	}
)

func intVal[T ~int | ~int32 | ~int64](u T) cty.Value {
	return cty.NumberIntVal(int64(u))
}

func SerialFunction(start int) function.Function {
	return function.New(&function.Spec{
		Params:   []function.Parameter{},
		VarParam: nil,
		Type: func(args []cty.Value) (cty.Type, error) {
			return cty.String, nil
		},
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			v := strconv.FormatInt(int64(start), 16)
			start += 1
			return cty.StringVal(v), nil
		},
	})
}

func makeStringHashFunction(hf func() hash.Hash, enc func([]byte) string) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{
				Name: "str",
				Type: cty.String,
			},
		},
		Type: function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, retType cty.Type) (ret cty.Value, err error) {
			s := args[0].AsString()
			h := hf()
			h.Write([]byte(s))
			rv := enc(h.Sum(nil))
			return cty.StringVal(rv), nil
		},
	})
}

var quoteFunc = function.New(&function.Spec{
	Params: []function.Parameter{{
		Name: "str",
		Type: cty.String,
	}},
	Type: function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		s := args[0].AsString()
		return cty.StringVal(fmt.Sprintf("%q", s)), nil
	},
})

var now = time.Now

var timeAfterFunc = function.New(&function.Spec{
	Params: []function.Parameter{{
		Name: "duration",
		Type: cty.String,
	}},
	Type: function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		d, err := times.ParseDuration(args[0].AsString())
		if err != nil {
			return cty.StringVal(""), err
		}
		tm := now().Add(d).Format(timestampFormat)
		return cty.StringVal(tm), nil
	},
})
