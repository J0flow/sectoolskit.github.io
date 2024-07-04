from flask import Flask, request, jsonify
import fmc

app = Flask(__name__)

@app.route('/process', methods=['POST'])
def process():
    data = request.form.to_dict()
    data['ip_addresses'] = data['ip_addresses'].split('\n')
    data['ticket_list'] = data['ticket_list'].split('\n')

    # Utilisation des fonctions de fmc.py
    source_ip, hostname, mac_address, action = fmc.parse_dhcp_message(data["dhcp_message"])

    if not source_ip or not hostname or not mac_address:
        return jsonify({'result': "Erreur : Impossible d'extraire les informations du payload DHCP."})

    tickets_info = "- Autre billets pour le même utilisateur ou la même machine sur les 30 derniers jours.\n" + "\n".join([f"  - {ticket}" for ticket in data["ticket_list"]]) if data["ticket_list"] else "- Aucun autre billet pour le même utilisateur ou la même machine sur les 30 derniers jours."

    intro_message = f"""

--------------------------------------------------------------
--------------------------------------------------------------

Bonjour,

[Description]
Description de l’incident de sécurité : Nous avons détecté des communications depuis l'interne vers plusieurs IP malicieuses externes sur une alerte FMC.
Description de l’offense : CISCO FMC - Security Intelligence Personnel vers Externe (10+)

[Niveau de Criticité]
Selon la matrice de sévérité: Moyen

[Catégorie]
SEC4: Code malicieux et Malware

[Actifs concernés]
Username: {data['username']}
Nom complet de l’utilisateur: {data['full_name']}
Fonction/Rôle : {data['role']}
Hostname de la machine : {hostname}
Adresse MAC : {mac_address}
Localisation/réseau de l’évènement: {data['location']}
IP source : {source_ip}

[Analyses du SOC]
Date : {data['date']}
Numéro de l’offense : {data['offense_number']}

IoC / évidences :"""

    results = []
    for ip in data['ip_addresses']:
        country = fmc.get_ip_info(ip)
        if country is None:
            results.append(f"{ip} was not found in the database")
            continue

        fraud_score = fmc.analyze_ip(ip)
        vpn = fmc.check_vpn(ip)
        vpn_status = 'VPN' if vpn else 'Non VPN'
        results.append(f"{ip}\tFraud Score {fraud_score}\t{country}\t{vpn_status}")

    for result in results:
        intro_message += result + "\n"

    ip_count = len(data['ip_addresses'])

    conclusion_message = f"""
Le poste de travail communique avec plus de {ip_count} IPs adresses catégorisées dans les Security intelligences du FMC.

Analyse sur le comportement:
Nous avons remarqué que l'IP source a tenté de communiquer avec plus de {data['blocked_ips_count']} IPs dans les dernieres 24h qui ont été bloquées par FMC.

[Actions à entreprendre pour le confinement]
- Nous recommandons d'isoler la machine.

[Actions à entreprendre pour la remédiation]
- Il est recommandé d’effectuer une analyse complète de la machine.

[Autres informations pertinentes]
{tickets_info}

Cordialement,

--------------------------------------------------------------
"""

    intro_message += conclusion_message

    ticket_title = f"[SOC UdeM][MOYEN]CISCO FMC - Security Intelligence Personnel vers Externe (10+) - {hostname}"
    intro_message += f"Titre du ticket: {ticket_title} \nCC : equipesoc@esitechnologies.com\n\n--------------------------------------------------------------"

    return jsonify({'result': intro_message})

if __name__ == '__main__':
    app.run(debug=True)
