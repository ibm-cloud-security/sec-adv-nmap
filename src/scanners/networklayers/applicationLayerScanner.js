const nmapScanner = require('../../../utils/nmapScanner')

module.exports = exporterFunction

function exporterFunction() {

    function scan(targetIps, additionalParameters, portRange) {

            return new Promise((resolve, reject) => {
                scnaWithNmapModule(targetIps, additionalParameters, portRange).then((scanResults) => {
                    resolve(scanResults)
                }).catch((error) => {
                    reject(error)
                })
            })

    }


    function scnaWithNmapModule(targetIps, additionalParameters, portRange) {

        return new Promise((resolve, reject) => {

            nmapScanner.useNmapModule(targetIps + additionalParameters + portRange+ ' -Pn -T4 -sU', '-sS').then((data) => {

                let totalHostsUp = data.length
                let scanResults = []

                for (let i = 0; i < totalHostsUp; i++) {
                    let totalOPenPortsOnHost = Object.values(data[i].openPorts).length
                    let targetIP = data[i].ip

                    for (let j = 0; j < totalOPenPortsOnHost; j++) {
                        let findings = {}
                        findings[targetIP] = [data[i].openPorts[j].port, data[i].openPorts[j].service]
                        scanResults.push(findings)
                    }
                }

                resolve(scanResults)

            }).catch((error) => {
                reject(error)
            })

        })

    }
    return {
        scan: scan,
    }

}