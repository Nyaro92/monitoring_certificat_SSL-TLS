from cryptography import x509
from cryptography.hazmat.primitives import hashes

def extract_extensions(certificat):
    ski_hex = None
    san_list = []
    cn = None

    try:
        ski_ext = certificat.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        ski_bytes = ski_ext.value.key_identifier
        ski_hex = ":".join([f"{b:02x}" for b in ski_bytes])
    except x509.ExtensionNotFound:
        pass

    fingerprint = certificat.fingerprint(hashes.SHA256()).hex()

    try:
        san_ext = certificat.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        san_list = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    try:
        cn_attrs = certificat.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)
        if cn_attrs:
            cn = cn_attrs[0].value
    except:
        pass

    return {
        "ski_hex": ski_hex,
        "fingerprint": fingerprint,
        "san_list": san_list,
        "common_name": cn
    }