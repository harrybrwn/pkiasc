package main

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-cty-funcs/cidr"
	"github.com/hashicorp/go-cty-funcs/crypto"
	"github.com/hashicorp/go-cty-funcs/encoding"
	"github.com/hashicorp/go-cty-funcs/uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/tryfunc"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"

	"gopkg.hrry.dev/pkiasc/internal/times"
)

func EvalContext(body hcl.Body) (*hcl.EvalContext, hcl.Diagnostics) {
	configContent, diags := body.Content(&ConfigSchema)
	if diags.HasErrors() {
		return nil, diags
	}

	var certificates = make(map[string]cty.Value)
	eval := &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"key_usage":     cty.ObjectVal(keyUsageConstants),
			"ext_key_usage": cty.ObjectVal(extKeyUsageConstants),
			"env":           envVars(),
		},
		Functions: stdlibFunctions,
	}

	// Collect and evaluate all constant expressions to put in variables
	for _, block := range configContent.Blocks {
		switch block.Type {
		case "var":
			continue
		case "certificate":
			content, diags := block.Body.Content(CertificateSchema)
			if diags.HasErrors() {
				return nil, diags
			}
			cert := make(map[string]cty.Value, len(content.Attributes)+len(content.Blocks))
			if len(block.Labels) < 1 {
				return nil, hcl.Diagnostics{{
					Severity: hcl.DiagError,
					Summary:  "invalid block",
					Detail:   "missing label value",
					Subject:  &block.TypeRange,
					Context:  &block.DefRange,
				}}
			}
			id := block.Labels[0]
			if _, ok := certificates[id]; ok {
				return nil, hcl.Diagnostics{{
					Severity: hcl.DiagError,
					Summary:  "duplicate block",
					Detail:   fmt.Sprintf("can't have more that one certificate named %q", id),
					Subject:  &block.LabelRanges[0],
					Context:  &block.DefRange,
				}}
			}

			cert["id"] = cty.StringVal(id)
			for _, attr := range content.Attributes {
				if !isConstExpr(attr.Expr) {
					continue
				}
				cert[attr.Name], diags = attr.Expr.Value(eval)
				if diags.HasErrors() {
					return nil, diags
				}
			}
			for _, blk := range content.Blocks {
				// TODO we might support other block types in the future
				attrs, diags := blk.Body.JustAttributes()
				if diags.HasErrors() {
					return nil, diags
				}
				inner := make(map[string]cty.Value, len(attrs))
				for _, attr := range attrs {
					if !isConstExpr(attr.Expr) {
						continue
					}
					inner[attr.Name], diags = attr.Expr.Value(eval)
					if diags.HasErrors() {
						return nil, diags
					}
				}
				cert[blk.Type] = cty.ObjectVal(inner)
			}
			certificates[id] = cty.ObjectVal(cert)

		default:
			return nil, hcl.Diagnostics{{
				Severity: hcl.DiagError,
				Subject:  &block.TypeRange,
				Context:  &block.DefRange,
				Summary:  "invalid block",
				Detail:   fmt.Sprintf("block type %q not recognized", block.Type),
			}}
		}
	}
	eval.Variables["certificate"] = cty.ObjectVal(certificates)
	return eval, nil
}

func envVars() cty.Value {
	m := map[string]cty.Value{}
	for _, pair := range os.Environ() {
		i := strings.Index(pair, "=")
		if i < 0 {
			continue
		}
		k := pair[:i]
		v := pair[i+1:]
		m[k] = cty.StringVal(v)
	}
	return cty.ObjectVal(m)
}

func isConstExpr(expr hcl.Expression) bool {
	for _, t := range expr.Variables() {
		switch t.RootName() {
		case "env", "key_usage", "ext_key_usage":
			continue
		default:
			return false
		}
	}
	return true
}

const timestampFormat = time.RFC3339Nano

var stdlibFunctions = map[string]function.Function{
	"abs":               stdlib.AbsoluteFunc,
	"add":               stdlib.AddFunc,
	"and":               stdlib.AndFunc,
	"base64decode":      encoding.Base64DecodeFunc,
	"base64encode":      encoding.Base64EncodeFunc,
	"bcrypt":            crypto.BcryptFunc,
	"byteslen":          stdlib.BytesLenFunc,
	"bytesslice":        stdlib.BytesSliceFunc,
	"can":               tryfunc.CanFunc,
	"ceil":              stdlib.CeilFunc,
	"chomp":             stdlib.ChompFunc,
	"chunklist":         stdlib.ChunklistFunc,
	"cidrhost":          cidr.HostFunc,
	"cidrnetmask":       cidr.NetmaskFunc,
	"cidrsubnet":        cidr.SubnetFunc,
	"cidrsubnets":       cidr.SubnetsFunc,
	"csvdecode":         stdlib.CSVDecodeFunc,
	"coalesce":          stdlib.CoalesceFunc,
	"coalescelist":      stdlib.CoalesceListFunc,
	"compact":           stdlib.CompactFunc,
	"concat":            stdlib.ConcatFunc,
	"contains":          stdlib.ContainsFunc,
	"distinct":          stdlib.DistinctFunc,
	"divide":            stdlib.DivideFunc,
	"element":           stdlib.ElementFunc,
	"equal":             stdlib.EqualFunc,
	"exec":              execFunc,
	"flatten":           stdlib.FlattenFunc,
	"floor":             stdlib.FloorFunc,
	"format":            stdlib.FormatFunc,
	"formatdate":        stdlib.FormatDateFunc,
	"formatlist":        stdlib.FormatListFunc,
	"indent":            stdlib.IndentFunc,
	"index":             stdlib.IndexFunc,
	"int":               stdlib.IntFunc,
	"join":              stdlib.JoinFunc,
	"jsondecode":        stdlib.JSONDecodeFunc,
	"jsonencode":        stdlib.JSONEncodeFunc,
	"keys":              stdlib.KeysFunc,
	"log":               stdlib.LogFunc,
	"length":            stdlib.LengthFunc,
	"lessthan":          stdlib.LessThanFunc,
	"lessthanorequalto": stdlib.LessThanOrEqualToFunc,
	"lookup":            stdlib.LookupFunc,
	"lower":             stdlib.LowerFunc,
	"now":               nowFunc,
	"max":               stdlib.MaxFunc,
	"merge":             stdlib.MergeFunc,
	"modulo":            stdlib.ModuloFunc,
	"min":               stdlib.MinFunc,
	"multiply":          stdlib.MultiplyFunc,
	"negate":            stdlib.NegateFunc,
	"notequal":          stdlib.NotEqualFunc,
	"not":               stdlib.NotFunc,
	"or":                stdlib.OrFunc,
	"parseint":          stdlib.ParseIntFunc,
	"pow":               stdlib.PowFunc,
	"quote":             quoteFunc,
	"range":             stdlib.RangeFunc,
	"regex":             stdlib.RegexFunc,
	"regexall":          stdlib.RegexAllFunc,
	"regex_replace":     stdlib.RegexReplaceFunc,
	"reverse":           stdlib.ReverseListFunc,
	"reverselist":       stdlib.ReverseListFunc,
	"setintersection":   stdlib.SetIntersectionFunc,
	"setproduct":        stdlib.SetProductFunc,
	"setsubtract":       stdlib.SetSubtractFunc,
	"setunion":          stdlib.SetUnionFunc,
	// TODO add a serial_strategy option that control how serial numbers are generated
	"serial":     SerialFunction(0x1000),
	"md5":        crypto.Md5Func,
	"sha1":       crypto.Sha1Func,
	"sha256":     crypto.Sha256Func,
	"sha512":     crypto.Sha512Func,
	"signum":     stdlib.SignumFunc,
	"slice":      stdlib.SliceFunc,
	"sort":       stdlib.SortFunc,
	"split":      stdlib.SplitFunc,
	"strlen":     stdlib.StrlenFunc,
	"strrev":     stdlib.ReverseFunc,
	"substr":     stdlib.SubstrFunc,
	"subtract":   stdlib.SubtractFunc,
	"timeadd":    stdlib.TimeAddFunc,
	"timeafter":  timeAfterFunc,
	"title":      stdlib.TitleFunc,
	"trim":       stdlib.TrimFunc,
	"trimprefix": stdlib.TrimPrefixFunc,
	"trimspace":  stdlib.TrimSpaceFunc,
	"trimsuffix": stdlib.TrimSuffixFunc,
	"try":        tryfunc.TryFunc,
	"upper":      stdlib.UpperFunc,
	"urlencode":  encoding.URLEncodeFunc,
	"uuidv4":     uuid.V4Func,
	"uuidv5":     uuid.V5Func,
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

var nowFunc = function.New(&function.Spec{
	Params: []function.Parameter{},
	Type:   function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		tm := now().Format(timestampFormat)
		return cty.StringVal(tm), nil
	},
})

var execFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "command", Type: cty.String},
	},
	VarParam: &function.Parameter{Name: "arguments", Type: cty.String},
	Type:     function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		var (
			buf       bytes.Buffer
			command   = args[0].AsString()
			arguments = make([]string, 0, len(args)-1)
		)
		for _, a := range args[1:] {
			arguments = append(arguments, a.AsString())
		}
		cmd := exec.Command(command, arguments...)
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		err := cmd.Run()
		if err != nil {
			return cty.NilVal, err
		}
		return cty.StringVal(buf.String()), nil
	},
})
