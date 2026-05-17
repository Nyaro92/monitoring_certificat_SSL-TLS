from .connection import get_certificate
from .parser import parse_certificate
from .calcul_expiration import analyze_certificate
from .extensions import extract_extensions
def chec_certificat(hostname, port=443):
    try:
        # Pour les connexion socket et sécurisation avec TLS/SSL 
        cert_bin = get_certificate(hostname, port)
        if cert_bin is None:
            return {"status": "DOWN", "error": "HOST DOWN"}

        # pour faire le parsing (lecture de bytes pour les rendre lisibles)
        data = parse_certificate(cert_bin)
        if data is None:
            return {"status": "ERROR", "error": "Parsing failed"}

        certificat = data["certificat_obj"]

        # calcul et analyse de l'expiration du certificat si l'éxpiration est proche 
        status = analyze_certificate(hostname,data["expirer"])

        # gestion des extensions du certificat
        extra = extract_extensions(certificat)

        # résultat final
        return {
            "status": "OK",
            "n_serie": data["n_serie"],
            "subject": data["subject"],
            "issuer": data["issuer"],
            "debut": data["debut"],
            "expirer": data["expirer"],
            "delais": status,
            "algo_sign": data["algo_sign"],
            "alg_pub_key": data["alg_pub_key"],
            **extra
        }

    except Exception as e:
        return {"status": "ERROR", "error": str(e)} 