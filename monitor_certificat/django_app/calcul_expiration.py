from datetime import datetime, timedelta, timezone
import requests
url_serveur="https://ntfy.sh/labo-nyaro-serveur44"
#priorité a des echelle 1 --> 5 , min ---> max 
def envoi_notif(message, priorite):
    requests.post(url_serveur, 
                      data=message,
                      headers={
                          "Title": "Certficat Information",
                          "Priority": str(priorite)
                      }
                      )
def analyze_certificate(hostname,expirer):
    delais = expirer - datetime.now(timezone.utc)

    if delais <= timedelta(days=0):
        envoi_notif(
            f"{hostname}--> Certificat Expirer : Renouvellemnt immédiat",
            5
        )
        return "EXPIRED"
    elif delais < timedelta(days=7):
        envoi_notif(
            f"{hostname}--> Certificat critique : expirer dans {delais}",
            4
        )
        return "CRITICAL"
    elif delais < timedelta(days=30):
        envoi_notif(
            f"{hostname} --> Certificat bientôt expirer : {delais} restants ",
            3
        )
        return "WARNING"
    else:
        return "OK"