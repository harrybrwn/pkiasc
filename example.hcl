store   = "./testdata/store"
keysize = 2048

var "country" {
	default = "united states"
}

certificate "ca" {
	ca            = true
	not_after     = timeafter("365d")
	not_before    = now()
	serial_number = serial()

	subject {
		common_name         = title("testing root CA")
		organization        = title(join(" ", [env.USER, "certificates", "inc."]))
		organizational_unit = env.USER
		country             = title(var.country)
	}
	key_usage = [
		key_usage.digital_signatures,
		key_usage.cert_sign,
	]
	# Default: "sha256-rsa"
	signature_algorithm = "sha256-rsa"
	# Default: "rsa"
	public_key_algorithm = "rsa"
}

certificate "intermediate" {
	issuer        = certificate.ca.id
	ca            = true
	serial_number = "ff93ac"
	not_after     = timeafter("2y1mo35ms")
	subject {
		common_name  = title("testing intermediate")
		organization = certificate.ca.subject.organization
	}
	key_usage = [
		key_usage.digital_signatures,
		key_usage.cert_sign,
	]
}

certificate "cert_1" {
	issuer        = certificate.intermediate.id
	serial_number = serial()
	not_after     = timeafter("1y4mo")
	subject {
		common_name         = "jimmy.me"
		organization        = certificate.ca.subject.organization
		organizational_unit = "Jimmy Jones of ${quote(certificate.ca.subject.organization)}"
	}
	ext_key_usage = [ext_key_usage.server_auth]
	dns = [
		"jimmy.me",
		"*.jimmy.me",
	]
	ocsp = [
		"http://ocsp:9988/"
	]
}

certificate "ocsp" {
	issuer        = certificate.intermediate.id
	serial_number = serial()
	not_after     = timeafter("1y4mo")
	key_usage = [
		key_usage.digital_signatures,
		key_usage.key_encipherment,
	]
	ext_key_usage = [ext_key_usage.ocsp_signing]
	subject {
		common_name  = "ocsp.default.svc.cluster.local"
		organization = certificate.ca.subject.organization
	}
}