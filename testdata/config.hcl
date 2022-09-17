store = "./testdata/store"
keysize = add(2048, 2048)

certificate "ca" {
	ca = true
	expires = "365d"
	serial_number = serial()
	subject {
		common_name = title("testing root CA")
		organization = title("harry brown")
		organizational_unit = env.USER
	}
	key_usage = [
		key_usage.digital_signatures,
		key_usage.cert_sign,
	]
}

certificate "intermediate" {
	expires = "365d"
	issuer = certificate.ca.id
	ca = true
	serial_number = serial()
	subject {
		common_name = title("testing intermediate")
		organization = certificate.ca.subject.organization
	}
	key_usage = [
		key_usage.digital_signatures,
		key_usage.cert_sign,
	]
}

certificate "cert_1" {
	expires = "365d"
	issuer = certificate.intermediate.id
	ca = false
	serial_number = serial()

	subject {
		common_name = "hrry.me"
		organization = certificate.ca.subject.organization
		organizational_unit = "HarryBrown ${certificate.ca.expires} ${certificate.ca.serial_number}"
	}

	ext_key_usage = [ext_key_usage.server_auth]
	dns = [
		"hrr.me",
		"*.hrry.me",
	]
	email = ["test@example.com"]
	ocsp = ["http://localhost:9999"]
}