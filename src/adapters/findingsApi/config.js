let config = {
    "apiKey" : process.env.apiKey,
    "accountId" : process.env.accountID,
    "providerId" : 'network-scan-nmap',
    "sectionName": 'Network',
    "cardId" : 'network-scan-nmap-Card',
    "cardTitle" : 'Port Discovery',
    "cardSubTitle" : 'Nmap',
    "findingsId_application" : "Nmap-application-layer-findings-type",
    "findingsId_transport" : "Nmap-transport-layer-findings-type",
    "findingsId_network" : "Nmap-network-layer-findings-type",
    "findingsId_datalink" : "Nmap-datalink-layer-findings-type",
    "findingSource" : "Nmap security scan tool",
}

module.exports.config = config




