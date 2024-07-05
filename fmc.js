// Utilisation de fetch pour effectuer des requêtes HTTP

// Fonction pour obtenir les informations de localisation via ip-api.com
async function getIpInfo(ipAddress) {
    const url = `https://ip-api.com/json/${ipAddress}`;
    try {
        const response = await fetch(url);
        if (response.status === 200) {
            const data = await response.json();
            console.log(`Données de ip-api pour ${ipAddress}:`, data);
            return data.country || 'N/A';
        } else {
            console.log(`Erreur lors de la récupération des données pour ${ipAddress}. Code d'état: ${response.status}`);
            return null;
        }
    } catch (error) {
        console.log(`Exception lors de la récupération des données pour ${ipAddress}:`, error);
        return null;
    }
}

// Fonction pour analyser le score de fraude via scamalytics.com
async function analyzeIp(ipAddress) {
    const url = `https://scamalytics.com/ip/${ipAddress}`;
    try {
        const response = await fetch(url);
        const text = await response.text();
        const parser = new DOMParser();
        const doc = parser.parseFromString(text, 'text/html');
        
        const scoreElement = doc.querySelector('div.score');
        let score = scoreElement ? scoreElement.textContent.trim() : 'Not Found';
        score = score.replace('Fraud Score:', '').trim();
        
        return score;
    } catch (error) {
        console.log(`Exception lors de l'analyse du score de fraude pour ${ipAddress}:`, error);
        return 'Not Found';
    }
}

// Fonction pour vérifier si l'IP est un VPN via proxycheck.io
async function checkVpn(ipAddress) {
    const url = `https://proxycheck.io/v2/${ipAddress}`;
    try {
        const response = await fetch(url);
        if (response.status === 200) {
            const data = await response.json();
            console.log(`Données de proxycheck.io pour ${ipAddress}:`, data);
            if (data[ipAddress] && 'proxy' in data[ipAddress]) {
                return data[ipAddress].proxy === 'yes';
            } else {
                console.log(`Erreur: Les données pour ${ipAddress} ne contiennent pas les informations attendues.`);
                return false;
            }
        } else {
            console.log(`Erreur lors de la vérification VPN pour ${ipAddress}. Code d'état: ${response.status}`);
            return false;
        }
    } catch (error) {
        console.log(`Exception lors de la vérification VPN pour ${ipAddress}:`, error);
        return false;
    }
}

// Fonction pour extraire les informations de l'offre DHCP
function parseDhcpMessage(dhcpMessage) {
    const offerMatch = dhcpMessage.match(/DHCPOFFER on ([\d\.]+) to ([\w:]+) \(([\w-]+)\)/);
    const requestMatch = dhcpMessage.match(/DHCPREQUEST for ([\d\.]+) from ([\w:]+) \(([\w-]+)\)/);
    
    if (offerMatch) {
        return {
            ipAddress: offerMatch[1],
            macAddress: offerMatch[2],
            hostname: offerMatch[3],
            action: "DHCPOFFER"
        };
    } else if (requestMatch) {
        return {
            ipAddress: requestMatch[1],
            macAddress: requestMatch[2],
            hostname: requestMatch[3],
            action: "DHCPREQUEST"
        };
    } else {
        return null;
    }
}

// Demander à l'utilisateur les informations de base
async function main() {
    console.log("Début de la fonction main");
    const date = prompt("Date :") || "non répertorié";
    const location = prompt("Localisation/réseau de l’évènement:") || "non répertorié";
    const offenseNumber = prompt("Numéro de l’offense :") || "non répertorié";
    const blockedIpsCount = prompt("Nombre d'IPs bloquées dans les dernières 24 heures :") || "non répertorié";

    const ipAddresses = [];
    while (true) {
        const ip = prompt("Veuillez entrer une adresse IP (appuyez sur Entrée pour terminer) :").trim();
        if (ip === "") break;
        ipAddresses.push(ip);
    }

    const dhcpMessage = prompt("Veuillez entrer le payload DHCP (DHCPOFFER ou DHCPREQUEST) :").trim();
    const dhcpInfo = parseDhcpMessage(dhcpMessage);
    
    let sourceIp, hostname, macAddress;
    if (dhcpInfo) {
        sourceIp = dhcpInfo.ipAddress;
        hostname = dhcpInfo.hostname;
        macAddress = dhcpInfo.macAddress;
    } else {
        console.log("Erreur : Impossible d'extraire les informations du payload DHCP.");
        sourceIp = "non répertorié";
        hostname = "non répertorié";
        macAddress = "non répertorié";
    }

    const username = prompt("Username:") || "non répertorié";
    const fullName = prompt("Nom complet de l’utilisateur:") || "non répertorié";
    const role = prompt("Fonction/Rôle :") || "non répertorié";

    const ticketList = [];
    while (true) {
        const ticket = prompt("Y a-t-il d'autres billets pour le même utilisateur et même machine sur les 30 derniers jours ?").trim();
        if (ticket === "") break;
        ticketList.push(ticket);
    }

    const ticketsInfo = ticketList.length
        ? "- Autre billets pour le même utilisateur ou la même machine sur les 30 derniers jours.\n" + ticketList.map(ticket => `  - ${ticket}`).join("\n")
        : "- Aucun autre billet pour le même utilisateur ou la même machine sur les 30 derniers jours.";

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

    console.log(introMessage);

    const resultsDiv = document.getElementById("results");
    if (resultsDiv) {
        resultsDiv.innerText = introMessage;
    } else {
        console.log("Erreur : L'élément 'results' n'a pas été trouvé dans le DOM.");
    }

    const results = [];
    for (const ip of ipAddresses) {
        const country = await getIpInfo(ip);
        if (country === null) {
            results.push(`${ip} was not found in the database`);
            continue;
        }

        const fraudScore = await analyzeIp(ip);
        const vpn = await checkVpn(ip);
        const vpnStatus = vpn ? 'VPN' : 'Non VPN';

        results.push(`${ip}\tFraud Score ${fraudScore}\t${country}\t${vpnStatus}`);
    }

    results.forEach(result => console.log(result));

    if (resultsDiv) {
        resultsDiv.innerText += "\n" + results.join("\n");
    }

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

    --------------------------------------------------------------
    `;

    console.log(conclusionMessage);

    if (resultsDiv) {
        resultsDiv.innerText += "\n" + conclusionMessage;
    }

    const ticketTitle = `[SOC UdeM][MOYEN]CISCO FMC - Security Intelligence Personnel vers Externe (10+) - ${hostname}`;
    console.log(`Titre du ticket: ${ticketTitle} \nCC : equipesoc@esitechnologies.com\n\n--------------------------------------------------------------`);

    if (resultsDiv) {
        resultsDiv.innerText += "\nTitre du ticket: " + ticketTitle;
    }
}

main();
