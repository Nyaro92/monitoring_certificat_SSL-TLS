from django.shortcuts import render,redirect, get_object_or_404
#from django_app.check_cert_x509 import chec_certificat
from django_app.main import chec_certificat
#importation des modeles (les tables) qu'on a créer dans models.py
from .models import Host, certificat
# Create your views here.

def index(request):
    resultat_cert = None
    erreur = None

    if request.method == 'POST':
        action = request.POST.get("action")
        hostname = request.POST.get("hostname")
        port = int(request.POST.get("port", 443))

        resultat_cert = chec_certificat(hostname, port)

        if resultat_cert.get("status") != "OK":
            erreur = resultat_cert.get("error")
            return render(request, 'index.html', {
                "certificat": None,
                "erreur": erreur
            })
        #Simple recherche d'un certificat
        if action == "chercher":
            return render(request, 'index.html', {
                "certificat": resultat_cert,
                "erreur": None
            })
          #création ou récupération du host à propos du nom de domaine à vérifier
        elif action == "ajouter":
            #récupération du certificat qui est dépendant du model Host
            # update_or_create si existant simple modification si n'existe pas création
            host_obj, created = Host.objects.get_or_create(
                hostname=hostname,
                port=port,
                defaults={"etat": "OK"}
            )
            certificat.objects.update_or_create(
                host=host_obj,
                defaults={
                    "n_serie": resultat_cert["n_serie"],
                    "subject": resultat_cert["subject"],
                    "date_debut": resultat_cert["debut"],
                    "date_expiration": resultat_cert["expirer"],
                    "algo_sign": resultat_cert["algo_sign"],
                    "alg_pub_key": resultat_cert["alg_pub_key"],
                    "empreinte": resultat_cert["fingerprint"]
                }
            )

            return render(request, 'index.html', {
                "certificat": resultat_cert,
                "erreur": None
            })

    return render(request, 'index.html', {
        "certificat": None,
        "erreur": None
    })
def accueil(request):
    return render(request,'accueil.html')
def monitoring(request):
    if request.method == 'POST':
        action=request.POST.get("action")
        host_id=request.POST.get("host_id")
        if action == "supprimer" and host_id:
            host=get_object_or_404(Host, id=host_id)
            host.delete()
            return redirect('monitoring')
    donnees_host=Host.objects.all()
    donnees_cert=certificat.objects.all()
    return render(request, 'monitoring.html', {
        'hosts': donnees_host,
        'certificats':donnees_cert
    })

