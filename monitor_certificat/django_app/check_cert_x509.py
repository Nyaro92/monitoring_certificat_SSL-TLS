import socket
import ssl
from datetime import datetime,timedelta, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
#pour les trucs haché
from cryptography.hazmat.primitives import hashes
def chec_certificat(hostname,port=443):
        """création d'un context SSLcontext qui sert contient des reglages par défauts sécuriser ,
        déstiné à ouvrir une connexion chiffré 
        """
        context= ssl.create_default_context()
        ski_hex=None
        cn=None
        san_list=[]
        #créaation d'un context socket normal avec la classe socket.socket
        try:
                    #connection.py
                    with socket.create_connection((hostname, int(port))) as sock:
                        """Création d'un context SSLSocket(instance de la classe SSLSocket) qui consiste 
                        à sécurisé un socket normal en SSL/TLS à l'aide du context qui contient les outils de paramétrage 
                        SSL/TLS pour mieux configurer le socket 
                        """
                        with context.wrap_socket(sock, server_hostname=hostname) as secured_sock:
                                  ####
                                        #Obtention du certificat distant 
                                        certificat_binaire=secured_sock.getpeercert(binary_form=True)
                                        certificat=x509.load_der_x509_certificate((certificat_binaire), default_backend())
                                                                #Identifiant de base
                                                # numéro de série 
                                        n_serie= certificat.serial_number
                                                #subject common name 
                                        subject=certificat.subject.rfc4514_string()
                                                

                                                                #temps de validation avec timezone 
                                                #debut de validation 
                                        debut=certificat.not_valid_before_utc
                                                #expiration du certificat
                                        expirer=certificat.not_valid_after_utc
                                                    #validation avec timezone 
                                        delais = expirer - datetime.now(timezone.utc)
                                        if delais <= timedelta(days=0):
                                            delais_expiration=f"Certificat déjà éxpirer !!!!"
                                        elif delais < timedelta(days=7):
                                            delais_expiration=f"Urgent !!! Certificat sous un état critique, expirer dans {delais}  "
                                        elif delais < timedelta(days=30):
                                            delais_expiration=f"Alerte !!! Certificat en danger , expirer dans {delais}"
                                        else:
                                            delais_expiration=f"Certificat éxpirer dans {delais}"
                                            #cryptographie 
                                        #Algorithme pour la signature 
                                        algo_sign=certificat.signature_algorithm_oid._name
                                        #Algorithme de la Clé public 
                                        alg_pub_key=certificat.public_key_algorithm_oid._name
                                                        #Identifiant Unique 
                                        #Subject key id
                                        try:
                                            ski_ext = certificat.extensions.get_extension_for_oid(
                                            x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
                                        )
                                            ski_bytes = ski_ext.value.key_identifier
                                            ski_hex = ":".join([f"{b:02x}" for b in ski_bytes])
                                        except x509.ExtensionNotFound:
                                            ski_hex=None
                                        #pour l'empreinte(fingerprint)
                                        fingerprint=certificat.fingerprint(hashes.SHA256()).hex()

                                                        #Nom d'autorité
                                        #SAN (Subject AlT Name)
                                        try:
                                            san_ext = certificat.extensions.get_extension_for_oid(
                                            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                                            )
                                            san_list = san_ext.value.get_values_for_type(x509.DNSName)
                                        except x509.ExtensionNotFound:
                                            san_list=[]
                                        #Common Name
                                        try:
                                            cn_attrs = certificat.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)
                                            if cn_attrs:
                                                cn=cn_attrs[0].value
                                        except:
                                                cn=None

                                        return {
                                            "status": "OK",
                                            "n_serie":n_serie,
                                            "subject": subject,
                                            "issuer":str(certificat.issuer),
                                            "debut":debut,
                                            "expirer":expirer,
                                            "delais":delais_expiration,
                                            "algo_sign":algo_sign,
                                            "alg_pub_key":alg_pub_key,
                                            "ski_hex":ski_hex,
                                            "fingerprint":fingerprint,
                                            "san_list":san_list,
                                            "common_name":cn
                                            }
        except ConnectionRefusedError:
            return {
                "status": "DOWN",
                "error": "STATUS DOWN"
            }
        except ssl.SSLError:
            return {
                "status": "SSLERROR",
                "error": "Ssl Error"
            }
        except socket.timeout:
            return {
                "status": "DOWN",
                "error": "STATUS DOWN"
            }
        except OSError:
            return {
                "status": "DOWN",
                "error": "STATUS DOWN"
            }
        except Exception as e:
             error=f"{e}"
             return{
                  "status":"error connexion",
                  "error": error
             }                    