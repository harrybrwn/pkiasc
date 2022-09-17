package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

var (
	// ConfigSchema, _      = gohcl.ImpliedBodySchema(&config{})
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
	SubjectSchema, _     = gohcl.ImpliedBodySchema(&Subject{})
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

func ParseConfig(c *config, content []byte, filename string) hcl.Diagnostics {
	f, diags := hclparse.NewParser().ParseHCL(content, filename)
	if diags.HasErrors() {
		return diags
	}
	eval := hcl.EvalContext{
		Variables: map[string]cty.Value{
			"key_usage":     cty.ObjectVal(keyUsageConstants),
			"ext_key_usage": cty.ObjectVal(extKeyUsageConstants),
			"env":           envVars(),
		},
		Functions: stdlibFunctions,
	}

	var (
		// Holds intermediate certificate runtime state used for variables
		certificate    = make(map[string]cty.Value)
		vars           = make(map[string]cty.Value)
		bodyContent, _ = f.Body.Content(&ConfigSchema)
	)

	if attr, ok := bodyContent.Attributes["keysize"]; ok {
		diags = gohcl.DecodeExpression(attr.Expr, &eval, &c.KeySize)
		if diags.HasErrors() {
			return diags
		}
	}

	if attr, ok := bodyContent.Attributes["store"]; ok {
		diags = gohcl.DecodeExpression(attr.Expr, &eval, &c.Store)
		if diags.HasErrors() {
			return diags
		}
	}

	for _, blk := range bodyContent.Blocks {
		switch blk.Type {
		case "var":
			name := blk.Labels[0]
			if !hclsyntax.ValidIdentifier(name) {
				return hcl.Diagnostics{{
					Severity: hcl.DiagError,
					Summary:  "Invalid variable name",
					Subject:  &blk.LabelRanges[0],
				}}
			}
			v := variable{Name: name}
			diags = gohcl.DecodeBody(blk.Body, eval.NewChild(), &v)
			if diags.HasErrors() {
				return diags
			}
			if v.Value != nil {
				vars[name], diags = v.Value.Expr.Value(&eval)
				if diags.HasErrors() {
					return diags
				}
			} else if v.Default != nil {
				vars[name], diags = v.Default.Expr.Value(&eval)
				if diags.HasErrors() {
					return diags
				}
			}
			eval.Variables["var"] = cty.ObjectVal(vars)
		case "certificate":
			id := blk.Labels[0]
			cert := Certificate{
				ID:      id,
				Version: 3,
			}
			values, diags := parseCertificate(eval.NewChild(), blk, &cert)
			if diags.HasErrors() {
				return diags
			}
			if _, ok := certificate[id]; ok {
				return hcl.Diagnostics{{
					Severity: hcl.DiagError,
					Summary:  "already defined",
					Detail:   "duplicate certificate block name",
					Subject:  &blk.LabelRanges[0],
				}}
			}
			c.Certificates = append(c.Certificates, cert)
			certificate[id] = values
			// update the certificate variable block for dynamic content
			eval.Variables["certificate"] = cty.ObjectVal(certificate)
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
	if len(c.Expires) == 0 && len(c.NotAfter) == 0 {
		return errors.New("certificate has no expiration")
	}
	return nil
}

func parseCertificate(eval *hcl.EvalContext, block *hcl.Block, cert *Certificate) (cty.Value, hcl.Diagnostics) {
	value := map[string]cty.Value{
		"id": cty.StringVal(block.Labels[0]),
	}
	var diags hcl.Diagnostics
	content, diagnostics := block.Body.Content(CertificateSchema)
	for _, attr := range content.Attributes {
		value[attr.Name], diags = attr.Expr.Value(eval)
		if diags.HasErrors() {
			diagnostics.Extend(diags)
			continue
		}
	}
	for _, blk := range content.Blocks {
		// TODO we might support other block types in the future
		attrs, diags := blk.Body.JustAttributes()
		if diags.HasErrors() {
			diagnostics.Extend(diags)
			continue
		}
		subvals := map[string]cty.Value{}
		for _, attr := range attrs {
			subvals[attr.Name], diags = attr.Expr.Value(eval)
			if diags.HasErrors() {
				diagnostics.Extend(diags)
				continue
			}
		}
		value[blk.Type] = cty.ObjectVal(subvals)
	}
	diags = gohcl.DecodeBody(block.Body, eval, cert)
	if diags.HasErrors() {
		diagnostics.Extend(diags)
	}
	err := validateCert(cert)
	if err != nil {
		return cty.NilVal, hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "invalid certificate",
			Detail:   err.Error(),
			Subject:  &block.DefRange,
			Context:  &block.TypeRange,
		}}
	}
	return cty.ObjectVal(value), diagnostics
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
