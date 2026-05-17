from cryptography import x509
from cryptography.hazmat.backends import default_backend

def parse_certificate(certificat_binaire):
    if certificat_binaire is None:
        return None

    certificat = x509.load_der_x509_certificate(certificat_binaire, default_backend())

    return {
        "certificat_obj": certificat,
        "n_serie": certificat.serial_number,
        "subject": certificat.subject.rfc4514_string(),
        "issuer": str(certificat.issuer),
        "debut": certificat.not_valid_before_utc,
        "expirer": certificat.not_valid_after_utc,
        "algo_sign": certificat.signature_algorithm_oid._name,
        "alg_pub_key": certificat.public_key_algorithm_oid._name
    }