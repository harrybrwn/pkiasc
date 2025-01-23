store   = "./testdata/store"
keysize = 2048

var "country" {
	default = "united states"
}

var "ocsp_server" {
	default = "http://localhost:8888"
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

	# certificate subject block
	subject {
		# common_name - certificate subject common name
		#
		# Default: ""
		common_name = title("testing root CA")
		# organization - certificate subject organization name
		#
		# Default: ""
		organization = title(join(" ", [env.USER, "certificates", "inc."]))
		# organizational_unit - certificate subject organizational unit
		#
		# Default: ""
		organizational_unit = env.USER
		# country - certificate subject country code
		#
		# Default: ""
		country = title(var.country)
		# locality - certificate subject locality
		#
		# Default: ""
		locality = ""
		# street_address - certificate subjecta street address
		#
		# Default: ""
		street_address = ""
		# postal_code - certificate subject postal code
		#
		# Default: ""
		postal_code = ""
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

certificate "alt_ca" {
	# cert_file - read the certificate from a file instead of generating one
	# using the propreties in the certificate block. If a file is spesified
	# here, all other attributes in the certificate block will be ignored.
	#
	# Default: ""
	cert_file = "testdata/pki0/ca.crt"
	# key_file - read the private key from this file instead of generating one
	#
	# Default: ""
	key_file = "testdata/pki0/ca.key"
}

certificate "intermediate" {
	# issuer - reference to the certificate ID to be used as the certificate
	# issuer.
	#
	# Default: ""
	issuer = certificate.ca.id
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
	ocsp = [var.ocsp_server]
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
		equal(var.ocsp_server, "") ? "http://ocsp:9988/" : var.ocsp_server
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
