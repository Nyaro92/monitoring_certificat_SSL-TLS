from django.db import models

# Create your models(ma table) here.
class Host(models.Model):
    hostname=models.CharField(max_length=280)
    port=models.IntegerField(default=443)
    etat=models.CharField(max_length=200, default="UNKNOWN")

    def __str__(self):
        return self.hostname
    
class certificat(models.Model):
    host           =models.OneToOneField(Host, on_delete=models.CASCADE, null=True)
    n_serie        =models.CharField(max_length=280)
    subject        =models.CharField(max_length=280)
    date_debut     =models.DateTimeField()
    date_expiration=models.DateTimeField()
    algo_sign      =models.CharField(max_length=280)
    alg_pub_key    =models.CharField(max_length=280)
    empreinte      =models.CharField(max_length=280)
    #pour rendre très lisibles en forme de text
    def __str__(self):
        return f"{self.host.hostname} - {self.status}"
    