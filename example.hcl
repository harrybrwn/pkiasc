store   = "./testdata/store"
keysize = 2048

var "country" {
	default = "united states"
}

certificate "ca" {
	# ca - marks the certificate as a Certificate Authority
	#
	# Default: false
	ca = true
	# path_len - set the pathlen in the certificate
	path_len = 0
	# not_after - certificate expiration date timestamp
	#
	# Default: ""
	not_after = timeafter("365d")
	# not_before - date that the certificate starts being valid
	#
	# Default: current date-time
	not_before = now()
	# serial_number - hex number used for cert serial number
	#
	# Default: ""
	serial_number = serial()

	subject {
		common_name         = title("testing root CA")
		organization        = title(join(" ", [env.USER, "certificates", "inc."]))
		organizational_unit = env.USER
		country             = title(var.country)
	}
	# key_usage - key usage
	#
	# Default: []
	key_usage = [
		key_usage.digital_signatures,
		key_usage.cert_sign,
	]
	# ext_key_usage - extended key usage
	#
	# Default: []
	ext_key_usage = []
	# signature_algorithm - algorithm to be used for generating the certificate
	# signagure
	#
	# Default: "sha256-rsa"
	signature_algorithm = "sha256-rsa"
	# public_key_algorithm - encryption algorithm of the certificate's public
	# key
	#
	# Default: "rsa"
	public_key_algorithm = "rsa"
}

certificate "intermediate" {
	# issuer - reference to the certificate ID to be used as the certificate
	# issuer.
	#
	# Default: ""
	issuer        = certificate.ca.id
	# path_len - set the pathlen in the certificate
	path_len      = 0
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