store = "./testdata/store"
keysize = 1024

var "country" {
	default = "United States"
}

certificate "ca" {
	ca = true
	not_after = timeafter("365d")
	serial_number = serial()
	subject {
		common_name = title("testing root CA")
		organization = title(join(" ", [env.USER, "certificates", "inc."]))
		organizational_unit = env.USER
		country = var.country
	}
	key_usage = [
		key_usage.digital_signatures,
		key_usage.cert_sign,
	]
	signature_algorithm = "sha256-rsa"
	public_key_algorithm = "rsa"
}

certificate "intermediate" {
	not_after = timeafter("365d")
	not_before = now()
	issuer = certificate.ca.id
	ca = true
	serial_number = serial()
	subject {
		common_name = exec("ls", "-a")
		organization = certificate.ca.subject.organization
	}
	key_usage = [
		key_usage.digital_signatures,
		key_usage.cert_sign,
	]
}

certificate "cert_1" {
	not_after = timeafter("365d")
	issuer = certificate.intermediate.id
	ca = false
	serial_number = serial()

	subject {
		common_name = "hrry.me"
		organization = certificate.ca.subject.organization
		organizational_unit = "HarryBrown ${certificate.ca.not_after} ${certificate.ca.serial_number}"
	}

	ext_key_usage = [ext_key_usage.server_auth]
	dns = [
		"hrr.me",
		"*.hrry.me",
	]
	email = ["test@example.com"]
	ocsp = ["http://localhost:9999"]
}