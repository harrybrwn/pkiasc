# pkiasc (PKI as Code)
Manage TLS certificates with a declarative plaintext interface.

## Setup
1. Write the configuration in `pki.hcl`.

```hcl
store = "./certificates"
keysize = 2048

var "org_name" {}

var "ocsp_url" {
    default = "http://localhost:8888"
}

certificate "ca" {
    ca            = true
    serial_number = serial()
    not_after     = timeafter("1y4mo")
    subject {
        organization = title(var.org_name)
    }
    key_usage = [
        key_usage.digital_signatures,
        key_usage.cert_sign,
    ]
    ocsp = [var.ocsp_url]
}

certificate "my_client" {
    issuer        = certificate.ca.id
    serial_number = serial()
    not_after     = timeafter("6mo48h")
    subject {
    common_name  = "Jimmy's Client Certificate"
        organization = certificate.ca.subject.organization
    }
    ext_key_usage = [
        ext_key_usage.client_auth
    ]
    ocsp = [var.ocsp_url]
}
```

2. Generate certificates.

```bash
pkiasc -c pki.hcl init --var 'org_name=Test Org'
```
