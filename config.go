package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

var (
	ConfigSchema = hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{
			{Name: "store", Required: true},
			{Name: "keysize", Required: true},
		},
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "certificate", LabelNames: []string{"id"}},
			{Type: "var", LabelNames: []string{"name"}},
		},
	}
	CertificateSchema, _ = gohcl.ImpliedBodySchema(&Certificate{})
)

type config struct {
	Store        string        `json:"store" hcl:"store"`
	KeySize      uint64        `json:"keysize" hcl:"keysize"`
	Certificates []Certificate `json:"certificates" hcl:"certificate,block"`
}

type variable struct {
	Name    string         `hcl:"name,label"`
	Default *hcl.Attribute `hcl:"default,optional"`
	Value   *hcl.Attribute `hcl:"value,optional"`
	Body    hcl.Body       `hcl:",body"`
}

func (v *variable) value(ctx *hcl.EvalContext) (cty.Value, hcl.Diagnostics) {
	if v.Value != nil {
		return v.Value.Expr.Value(ctx)
	} else if v.Default != nil {
		return v.Default.Expr.Value(ctx)
	}
	return cty.NilVal, nil
}

func ParseConfig(c *config, filename string, content []byte, inputList []string) hcl.Diagnostics {
	f, diags := hclparse.NewParser().ParseHCL(content, filename)
	if diags.HasErrors() {
		return diags
	}
	eval, diags := EvalContext(f.Body)
	if diags.HasErrors() {
		return diags
	}

	var vars = make(map[string]cty.Value)
	input, err := parseVarInput(inputList, eval)
	if err != nil {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "invalid input variable",
			Detail:   err.Error(),
		}}
	}
	bodyContent, diags := f.Body.Content(&ConfigSchema)
	if diags.HasErrors() {
		return diags
	}

	if attr, ok := bodyContent.Attributes["keysize"]; ok {
		diags = gohcl.DecodeExpression(attr.Expr, eval, &c.KeySize)
		if diags.HasErrors() {
			return diags
		}
	}
	if attr, ok := bodyContent.Attributes["store"]; ok {
		diags = gohcl.DecodeExpression(attr.Expr, eval, &c.Store)
		if diags.HasErrors() {
			return diags
		}
	}

	for _, blk := range bodyContent.Blocks {
		switch blk.Type {
		case "var":
			v, diags := parseVariable(eval, blk)
			if diags.HasErrors() {
				return diags
			}
			if val, ok := input[v.Name]; ok {
				vars[v.Name] = val
			} else {
				vars[v.Name], diags = v.value(eval)
				if diags.HasErrors() {
					return diags
				}
			}
			eval.Variables["var"] = cty.ObjectVal(vars)

		case "template":
			return hcl.Diagnostics{{
				Severity: hcl.DiagError,
				Summary:  "invalid block",
				Detail:   "certificate templates are not yet supported",
				Subject:  &blk.TypeRange,
				Context:  &blk.DefRange,
			}}

		case "certificate":
			id := blk.Labels[0]
			cert := Certificate{
				ID:      id,
				Version: 3,
			}
			sub := eval.NewChild()
			diags = gohcl.DecodeBody(blk.Body, sub, &cert)
			if diags.HasErrors() {
				return diags
			}
			err := validateCert(&cert)
			if err != nil {
				return hcl.Diagnostics{{
					Severity: hcl.DiagError,
					Summary:  "invalid certificate",
					Detail:   err.Error(),
					Subject:  &blk.DefRange,
					Context:  &blk.TypeRange,
				}}
			}
			c.Certificates = append(c.Certificates, cert)

		default:
			return hcl.Diagnostics{{
				Severity: hcl.DiagError,
				Subject:  &blk.TypeRange,
				Context:  &blk.DefRange,
				Summary:  "invalid block",
				Detail:   fmt.Sprintf("block type %q not recognized", blk.Type),
			}}
		}
	}
	return nil
}

func validateCert(c *Certificate) error {
	if len(c.NotAfter) == 0 {
		return errors.New("certificate has no expiration")
	}
	return nil
}

func parseVariable(eval *hcl.EvalContext, block *hcl.Block) (*variable, hcl.Diagnostics) {
	name := block.Labels[0]
	if !hclsyntax.ValidIdentifier(name) {
		return nil, hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Invalid variable name",
			Subject:  &block.LabelRanges[0],
		}}
	}
	v := variable{Name: name}
	diags := gohcl.DecodeBody(block.Body, eval.NewChild(), &v)
	if diags.HasErrors() {
		return nil, diags
	}
	return &v, nil
}

func parseVarInput(list []string, eval *hcl.EvalContext) (map[string]cty.Value, error) {
	m := make(map[string]cty.Value)
	for _, item := range list {
		item = strings.TrimLeft(item, " \t")
		i := strings.Index(item, "=")

		v := item[i+1:]
		k := item[:i]
		switch v {
		case "true", "false":
			val, err := strconv.ParseBool(v)
			if err != nil {
				return nil, err
			}
			m[k] = cty.BoolVal(val)
		default:
			if v[0] == '[' {
				expr, diags := hclsyntax.ParseExpression([]byte(v), "", hcl.InitialPos)
				if diags.HasErrors() {
					return nil, errors.New("failed to parse array syntax")
				}
				val, diags := expr.Value(eval)
				if diags.HasErrors() {
					return nil, errors.New("failed to parse array syntax")
				}
				m[k] = val
			} else if v[0] >= 48 && v[0] <= 57 {
				val, err := strconv.ParseInt(v, 10, 64)
				if errors.Is(err, strconv.ErrSyntax) {
					m[k] = cty.StringVal(v)
				} else if err != nil {
					return nil, err
				}
				m[k] = cty.NumberIntVal(val)
			} else {
				m[k] = cty.StringVal(v)
			}
		}
	}
	return m, nil
}
