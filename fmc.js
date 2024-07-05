document.getElementById('scriptForm').addEventListener('submit', async function (e) {
    e.preventDefault();
    
    const date = document.getElementById('date').value || "non répertorié";
    const location = document.getElementById('location').value || "non répertorié";
    const offenseNumber = document.getElementById('offenseNumber').value || "non répertorié";
    const blockedIpsCount = document.getElementById('blockedIpsCount').value || "non répertorié";
    const ipAddresses = document.getElementById('ipAddresses').value.split(',').map(ip => ip.trim());
    const dhcpMessage = document.getElementById('dhcpMessage').value.trim();
    const username = document.getElementById('username').value || "non répertorié";
    const fullName = document.getElementById('fullName').value || "non répertorié";
    const role = document.getElementById('role').value || "non répertorié";
    const ticketList = document.getElementById('ticketList').value.split(',').map(ticket => ticket.trim());

    const dhcpInfo = parseDhcpMessage(dhcpMessage);
    const sourceIp = dhcpInfo[0] || "non répertorié";
    const hostname = dhcpInfo[1] || "non répertorié";
    const macAddress = dhcpInfo[2] || "non répertorié";
    const action = dhcpInfo[3] || "non répertorié";

    const ticketsInfo = ticketList.length ? 
        "- Autre billets pour le même utilisateur ou la même machine sur les 30 derniers jours.\n" + ticketList.map(ticket => `  - ${ticket}`).join("\n") : 
        "- Aucun autre billet pour le même utilisateur ou la même machine sur les 30 derniers jours.";

    const introMessage = `
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
Username: ${username}
Nom complet de l’utilisateur: ${fullName}
Fonction/Rôle : ${role}
Hostname de la machine : ${hostname}
Adresse MAC : ${macAddress}
Localisation/réseau de l’évènement: ${location}
IP source : ${sourceIp}

[Analyses du SOC]
Date : ${date}
Numéro de l’offense : ${offenseNumber}

IoC / évidences :`;

    document.getElementById('result').innerText = introMessage;

    const results = [];
    for (const ip of ipAddresses) {
        const country = await getIpInfo(ip);
        const fraudScore = await analyzeIp(ip);
        const vpn = await checkVpn(ip);

        const vpnStatus = vpn ? 'VPN' : 'Non VPN';
        results.push(`${ip}\tFraud Score ${fraudScore}\t${country}\t${vpnStatus}`);
    }

    results.forEach(result => {
        const p = document.createElement('p');
        p.innerText = result;
        document.getElementById('result').appendChild(p);
    });

    const ipCount = ipAddresses.length;
    const conclusionMessage = `
Le poste de travail communique avec plus de ${ipCount} IPs adresses catégorisées dans les Security intelligences du FMC.

Analyse sur le comportement:
Nous avons remarqué que l'IP source a tenté de communiquer avec plus de ${blockedIpsCount} IPs dans les dernieres 24h qui ont été bloquées par FMC.

[Actions à entreprendre pour le confinement]
- Nous recommandons d'isoler la machine.

[Actions à entreprendre pour la remédiation]
- Il est recommandé d’effectuer une analyse complète de la machine.

[Autres informations pertinentes]
${ticketsInfo}

Cordialement,

--------------------------------------------------------------`;

    document.getElementById('result').append(conclusionMessage);

    const ticketTitle = `[SOC UdeM][MOYEN]CISCO FMC - Security Intelligence Personnel vers Externe (10+) - ${hostname}`;
    const titleElement = document.createElement('h2');
    titleElement.innerText = `Titre du ticket: ${ticketTitle} \nCC : equipesoc@esitechnologies.com\n\n--------------------------------------------------------------`;
    document.getElementById('result').appendChild(titleElement);
});

async function getIpInfo(ip) {
    const response = await fetch(`http://ip-api.com/json/${ip}`);
    if (response.ok) {
        const data = await response.json();
        return data.country || 'N/A';
    } else {
        console.error(`Erreur lors de la récupération des données pour ${ip}. Code d'état: ${response.status}`);
        return 'N/A';
    }
}

async function analyzeIp(ip) {
    const response = await fetch(`https://scamalytics.com/ip/${ip}`);
    const text = await response.text();
    const parser = new DOMParser();
    const doc = parser.parseFromString(text, 'text/html');
    const scoreElement = doc.querySelector('.score');
    return scoreElement ? scoreElement.textContent.replace('Fraud Score:', '').trim() : 'Not Found';
}

async function checkVpn(ip) {
    const response = await fetch(`https://proxycheck.io/v2/${ip}`);
    if (response.ok) {
        const data = await response.json();
        return data[ip] && data[ip].proxy === 'yes';
    } else {
        console.error(`Erreur lors de la vérification VPN pour ${ip}. Code d'état: ${response.status}`);
        return false;
    }
}

function parseDhcpMessage(dhcpMessage) {
    const offerMatch = dhcpMessage.match(/DHCPOFFER on ([\d\.]+) to ([\w:]+) \(([\w-]+)\)/);
    const requestMatch = dhcpMessage.match(/DHCPREQUEST for ([\d\.]+) from ([\w:]+) \(([\w-]+)\)/);

    if (offerMatch) {
        return [offerMatch[1], offerMatch[3], offerMatch[2], "DHCPOFFER"];
    } else if (requestMatch) {
        return [requestMatch[1], requestMatch[3], requestMatch[2], "DHCPREQUEST"];
    } else {
        return [null, null, null, null];
    }
}
