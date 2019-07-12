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

            nmapScanner.useNmapModule(targetIps + additionalParameters + portRange + ' -Pn -T4 -sU', '-sS').then((data) => {

                let totalHostsUp = data.length
                let openPortAndHost = []
                let scanResults = []

                for (let i = 0; i < totalHostsUp; i++) {
                    let totalOPenPortsOnHost = Object.values(data[i].openPorts).length
                    let targetIP = data[i].ip

                    for (let j = 0; j < totalOPenPortsOnHost; j++) {
                        portDetail = {}
                        portDetail[targetIP] = [data[i].openPorts[j].port, data[i].openPorts[j].service]
                        openPortAndHost.push(portDetail)
                    }
                }

                for (let k = 0; k < openPortAndHost.length; k++) {
                    if (Object.values(openPortAndHost[k])[0][1] === 'ppp') {
                        scanResults.push(openPortAndHost[k])
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