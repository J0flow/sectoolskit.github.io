async function getIpInfo(ipAddress) {
    const url = `http://ip-api.com/json/${ipAddress}`;
    try {
        const response = await axios.get(url);
        if (response.status === 200) {
            const data = response.data;
            const country = data.country || 'N/A';
            return country;
        } else {
            return null;
        }
    } catch (error) {
        console.error(error);
        return null;
    }
}

async function analyzeIp(ipAddress) {
    const url = `https://scamalytics.com/ip/${ipAddress}`;
    try {
        const response = await axios.get(url);
        const $ = cheerio.load(response.data);
        const scoreElement = $('div.score');
        let score = scoreElement.text().trim();
        if (score) {
            score = score.replace('Fraud Score:', '').trim();
        } else {
            score = 'Not Found';
        }
        return score;
    } catch (error) {
        console.error(error);
        return 'Not Found';
    }
}

async function checkVpn(ipAddress) {
    const url = `https://proxycheck.io/v2/${ipAddress}`;
    try {
        const response = await axios.get(url);
        if (response.status === 200) {
            const data = response.data;
            if (data[ipAddress] && 'proxy' in data[ipAddress]) {
                return data[ipAddress].proxy === 'yes';
            } else {
                return false;
            }
        } else {
            return false;
        }
    } catch (error) {
        console.error(error);
        return false;
    }
}

function parseDhcpMessage(dhcpMessage) {
    const offerMatch = dhcpMessage.match(/DHCPOFFER on ([\d\.]+) to ([\w:]+) \(([\w-]+)\)/);
    const requestMatch = dhcpMessage.match(/DHCPREQUEST for ([\d\.]+) from ([\w:]+) \(([\w-]+)\)/);

    let ipAddress, macAddress, hostname, action;

    if (offerMatch) {
        ipAddress = offerMatch[1];
        macAddress = offerMatch[2];
        hostname = offerMatch[3];
        action = "DHCPOFFER";
    } else if (requestMatch) {
        ipAddress = requestMatch[1];
        macAddress = requestMatch[2];
        hostname = requestMatch[3];
        action = "DHCPREQUEST";
    } else {
        return [null, null, null, null];
    }

    return [ipAddress, hostname, macAddress, action];
}

async function fmcScript(ipAddress, macAddress, hostname, dhcpMessage) {
    const country = await getIpInfo(ipAddress);
    const fraudScore = await analyzeIp(ipAddress);
    const vpnStatus = await checkVpn(ipAddress);
    const dhcpInfo = parseDhcpMessage(dhcpMessage);

    return `
        <p><strong>Country:</strong> ${country}</p>
        <p><strong>Fraud Score:</strong> ${fraudScore}</p>
        <p><strong>VPN Detected:</strong> ${vpnStatus ? 'Yes' : 'No'}</p>
        <p><strong>MAC Address:</strong> ${macAddress}</p>
        <p><strong>Hostname:</strong> ${hostname}</p>
        <p><strong>DHCP Info:</strong> IP Address: ${dhcpInfo[0]}, Hostname: ${dhcpInfo[1]}, MAC Address: ${dhcpInfo[2]}, Action: ${dhcpInfo[3]}</p>
    `;
}
