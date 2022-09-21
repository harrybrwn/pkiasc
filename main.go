package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

func main() {
	c := NewRootCmd()
	if err := c.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func NewRootCmd() *cobra.Command {
	var (
		configFiles = []string{"pki.hcl"}
		config      config
		varList     = make([]string, 0)
	)
	c := cobra.Command{
		Use:           "pki",
		Short:         `A cli tool for managing lots of ssl certificates.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			for _, filename := range configFiles {
				f, err := os.Open(filename)
				if err != nil {
					return err
				}
				defer f.Close()
				bytes, err := io.ReadAll(f)
				if err != nil {
					return err
				}
				diags := ParseConfig(&config, filename, bytes, varList)
				if diags.HasErrors() {
					return diags
				}
			}
			return nil
		},
	}
	f := c.PersistentFlags()
	f.StringArrayVarP(&configFiles, "config", "c", configFiles, "configuration file")
	f.StringVar(&config.Store, "store", config.Store, "base storage directory")
	f.StringSliceVarP(&varList, "var", "v", varList, "set variable values via the command line")
	c.AddCommand(
		newInitCmd(&config),
		newConfigCmd(&config),
	)
	return &c
}

func newInitCmd(config *config) *cobra.Command {
	var overwrite bool
	c := cobra.Command{
		Use:   "init",
		Short: "Initialize a new certificate store.",
		RunE: func(*cobra.Command, []string) error {
			var (
				err   error
				store = newStore(config)
			)
			if err = store.validate(); err != nil {
				return err
			}
			if err = store.init(overwrite); err != nil {
				return err
			}
			return nil
		},
	}
	c.Flags().BoolVarP(&overwrite, "overwrite", "O", overwrite, "overwrite all existing certificates and keys")
	return &c
}

func newConfigCmd(config *config) *cobra.Command {
	c := cobra.Command{
		Use:   "config",
		Short: "View configuration",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var (
				err error
				raw []byte
			)
			raw, err = json.MarshalIndent(config, "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s", raw)
			return nil
		},
	}
	return &c
}

func newStore(c *config) *store {
	s := store{
		dir:     c.Store,
		keySize: c.KeySize,
		roots:   make(map[string]Certificate),
		certs:   make([]Certificate, 0, len(c.Certificates)),
		issuers: make(map[string]issuer),
	}
	for _, cert := range c.Certificates {
		if cert.CA || len(cert.IssuerID) == 0 {
			cert.CA = true
			s.roots[cert.ID] = cert
		} else {
			s.certs = append(s.certs, cert)
		}
	}
	return &s
}

type Certificate struct {
	// Configuration metadata
	ID       string `json:"id" hcl:"id,label"`
	IssuerID string `json:"issuer" hcl:"issuer,optional"`
	KeyFile  string `json:"key_file" hcl:"key_file,optional"`

	// CSR template options
	Version      int     `json:"version" hcl:"version,optional"`
	SerialNumber string  `json:"serial_number" hcl:"serial_number,optional"`
	Subject      Subject `json:"subject" hcl:"subject,block"`
	CA           bool    `json:"ca" hcl:"ca,optional"`
	MaxPathLen   int     `json:"max_path_len,omitempty" hcl:"max_path_len,optional"`

	NotAfter  string `json:"not_after" hcl:"not_after,optional"`
	NotBefore string `json:"not_before" hcl:"not_before,optional"`

	KeyUsage    []x509.KeyUsage    `json:"key_usage,omitempty" hcl:"key_usage,optional"`
	ExtKeyUsage []x509.ExtKeyUsage `json:"ext_key_usage,omitempty" hcl:"ext_key_usage,optional"`

	DNS   []string `json:"dns,omitempty" hcl:"dns,optional"`
	Email []string `json:"email,omitempty" hcl:"email,optional"`
	IPs   []string `json:"ips,omitempty" hcl:"ips,optional"`
	URIs  []string `json:"uris,omitempty" hcl:"uris,optional"`

	OCSP                  []string                `json:"ocsp" hcl:"ocsp,optional"`
	IssuingCertificateURL []string                `json:"issuing_cert_url" hcl:"issuing_cert_url,optional"`
	CRLDistributionPoints []string                `json:"crl_distribution_points" hcl:"crl_distribution_points,optional"`
	PolicyIdentifiers     []asn1.ObjectIdentifier `json:"policy_identifiers" hcl:"policy_identifiers,optional"`
}

type Subject struct {
	CommonName         string `json:"common_name" hcl:"common_name,optional"`
	Organization       string `json:"organization,omitempty" hcl:"organization,optional"`
	OrganizationalUnit string `json:"organizational_unit,omitempty" hcl:"organizational_unit,optional"`
	Country            string `json:"country,omitempty" hcl:"country,optional"`
	Locality           string `json:"locality,omitempty" hcl:"locality,optional"`
	Province           string `json:"province,omitempty" hcl:"province,optional"`
	StreetAddress      string `json:"street_address,omitempty" hcl:"street_address,optional"`
	PostalCode         string `json:"postal_code,omitempty" hcl:"postal_code,optional"`
}

func (crt *Certificate) subject() pkix.Name {
	s := crt.Subject
	subj := pkix.Name{
		CommonName: s.CommonName,
	}
	if len(s.Organization) > 0 {
		subj.Organization = append(subj.Organization, s.Organization)
	}
	if len(s.OrganizationalUnit) > 0 {
		subj.OrganizationalUnit = append(subj.OrganizationalUnit, s.OrganizationalUnit)
	}
	if len(s.Country) > 0 {
		subj.Country = append(subj.Country, s.Country)
	}
	if len(s.Locality) > 0 {
		subj.Locality = append(subj.Locality, s.Locality)
	}
	if len(s.Province) > 0 {
		subj.Province = append(subj.Province, s.Province)
	}
	if len(s.StreetAddress) > 0 {
		subj.StreetAddress = append(subj.StreetAddress, s.StreetAddress)
	}
	if len(s.PostalCode) > 0 {
		subj.PostalCode = append(subj.PostalCode, s.PostalCode)
	}
	return subj
}

type store struct {
	dir     string
	keySize uint64
	certs   []Certificate
	roots   map[string]Certificate
	issuers map[string]issuer
}

type issuer struct {
	crt *x509.Certificate
	key crypto.PrivateKey
}

func (s *store) validate() error {
	for _, cert := range s.roots {
		if cert.NotAfter == "" {
			return errors.New("empty expiration date")
		}
	}
	return nil
}

func (s *store) init(overwrite bool) error {
	err := os.MkdirAll(s.dir, 0744)
	if err != nil && !os.IsExist(err) {
		return err
	}
	sha1Hash := sha1.New()
	for _, cert := range s.roots {
		caPath := filepath.Join(s.dir, cert.ID)
		keyPath := filepath.Join(s.dir, cert.ID, fmt.Sprintf("%s.key", cert.ID))
		crtFile := filepath.Join(s.dir, cert.ID, fmt.Sprintf("%s.crt", cert.ID))
		err = os.Mkdir(caPath, 0744)
		if err != nil && !os.IsExist(err) {
			return err
		}
		if exists(crtFile) && !overwrite {
			crt, err := OpenCertificate(crtFile)
			if err != nil {
				return err
			}
			k, err := OpenKey(keyPath)
			if err != nil {
				return err
			}
			s.issuers[cert.ID] = issuer{crt: crt, key: k}
			continue
		}

		template, err := newTemplate(&cert)
		if err != nil {
			return fmt.Errorf("failed to create certificate template: %w", err)
		}
		key, err := rsa.GenerateKey(rand.Reader, int(s.keySize))
		if err != nil {
			return err
		}
		pubBytes, err := asn1.Marshal(key.PublicKey)
		if err != nil {
			return err
		}
		sha1Hash.Reset()
		_, err = sha1Hash.Write(pubBytes)
		if err != nil {
			return err
		}
		template.AuthorityKeyId = sha1Hash.Sum(nil)

		derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			return err
		}
		s.issuers[cert.ID] = issuer{crt: template, key: key}
		if err = WriteCertificate(crtFile, derBytes); err != nil {
			return err
		}
		if err = WriteKey(keyPath, key); err != nil {
			return err
		}
	}

	for _, cert := range s.certs {
		crtPath := filepath.Join(s.dir, fmt.Sprintf("%s.pem", cert.ID))
		keyPath := filepath.Join(s.dir, fmt.Sprintf("%s.key", cert.ID))
		if exists(crtPath) && exists(keyPath) && !overwrite {
			fmt.Println("already exists", crtPath)
			continue
		}
		issuer, ok := s.issuers[cert.IssuerID]
		if !ok {
			return fmt.Errorf("could not find issuer %q", cert.IssuerID)
		}
		template, err := newTemplate(&cert)
		if err != nil {
			return err
		}
		key, err := rsa.GenerateKey(rand.Reader, int(s.keySize))
		if err != nil {
			return err
		}
		derBytes, err := x509.CreateCertificate(rand.Reader, template, issuer.crt, &key.PublicKey, issuer.key)
		if err != nil {
			return err
		}
		if err = WriteCertificate(crtPath, derBytes); err != nil {
			return err
		}
		if err = WriteKey(keyPath, key); err != nil {
			return err
		}
	}
	return nil
}

func newTemplate(cert *Certificate) (*x509.Certificate, error) {
	var (
		err                 error
		notBefore, notAfter time.Time
	)
	if cert.NotBefore == "" {
		notBefore = time.Now()
	}
	if len(cert.NotAfter) > 0 {
		notAfter, err = time.Parse(timestampFormat, cert.NotAfter)
		if err != nil {
			return nil, err
		}
	}

	serial, ok := new(big.Int).SetString(cert.SerialNumber, 16)
	if !ok {
		return nil, fmt.Errorf("could not parse serial number %q", cert.SerialNumber)
	}
	var (
		usage x509.KeyUsage
		ips   = make([]net.IP, 0, len(cert.IPs))
		uris  = make([]*url.URL, 0, len(cert.URIs))
	)
	for _, u := range cert.KeyUsage {
		usage |= u
	}
	for _, ip := range cert.IPs {
		ips = append(ips, net.ParseIP(ip))
	}
	for _, uri := range cert.URIs {
		u, err := url.Parse(uri)
		if err != nil {
			return nil, err
		}
		uris = append(uris, u)
	}

	return &x509.Certificate{
		Version:               cert.Version,
		IsCA:                  cert.CA,
		BasicConstraintsValid: cert.CA,
		SerialNumber:          serial,
		Subject:               cert.subject(),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              usage,
		ExtKeyUsage:           cert.ExtKeyUsage,
		DNSNames:              cert.DNS,
		IPAddresses:           ips,
		EmailAddresses:        cert.Email,
		URIs:                  uris,
		CRLDistributionPoints: cert.CRLDistributionPoints,
		PolicyIdentifiers:     cert.PolicyIdentifiers,
	}, nil
}

func exists(pathname string) bool {
	_, err := os.Stat(pathname)
	return !os.IsNotExist(err)
}
