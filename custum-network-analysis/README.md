# Network analysis exporter

L'exporter Network Analyser est un outil spécialisé dans l'analyse des logs Nginx pour détecter des activités réseau suspectes. Au lieu de capturer directement le trafic brut, il lit et filtre les fichiers d'accès serveur (access.log), extrait les adresses IP des requêtes, et compte leur fréquence d'apparition sur un intervalle de temps défini. Lorsqu'une IP effectue plus d'un certain nombre de tentatives (par exemple, plus de 10 accès) dans une courte fenêtre temporelle (10s), elle est identifiée comme potentiellement malveillante. Ce fonctionnement permet de surveiller efficacement des comportements anormaux ou des attaques automatisées (comme du brute force ou du scanning massif) en s'appuyant uniquement sur l'exploitation intelligente des logs existants, sans avoir besoin de modifier l'infrastructure réseau. Écrit en Python de manière simple et lisible, le script est facilement modifiable par n'importe quel utilisateur souhaitant adapter les règles de détection, enrichir les filtres, ou affiner le traitement des données en fonction de besoins spécifiques.

# Document d'exploration

https://prometheus.github.io/client_python/collector/custom/

https://medium.com/globant/creating-a-prometheus-custom-exporter-using-python-and-adding-it-using-service-discovery-b43be8c875af