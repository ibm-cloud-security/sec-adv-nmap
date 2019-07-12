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
            //try quick IP scan
            nmapScanner.useNmapModule(targetIps + additionalParameters + portRange + ' -PE -PS443 -PA80', '-PP').then((data) => {
                //in combination will not even give[], when mac targetted alone the will give []

                let totalHostsUp = data.length
                let totalArpHostsUp = 0
                let scanResults = []

                if (totalHostsUp > 0) {
                    //ARP scan
                    nmapScanner.useNmapModule(targetIps + additionalParameters + portRange, '-PR').then((arpData) => {
                        totalArpHostsUp = arpData.length

                        if (totalArpHostsUp === 0) {

                            for (let j = 0; j < totalHostsUp; j++) {
                                let findings = { "Host available via IP : ": data[j].ip }
                                scanResults.push(findings)
                            }
                        } else {
                            let arpIps = [] //to exclude form total hosts for IP
                            for (let w = 0; w < totalArpHostsUp; w++) {
                                arpIps.push(arpData[w].ip)
                            }
                            //add ARP hosts in finding
                            for (let m = 0; m < totalArpHostsUp; m++) {
                                let findings = { "Host available via ARP : ": arpData[m].ip }
                                scanResults.push(findings)
                            }
                            //add IP hosts in findings
                            for (let n = 0; n < totalHostsUp; n++) {
                                if (!arpIps.includes(data[n].ip)) {
                                    let findings = { "Host available via IP : ": data[n].ip }
                                    scanResults.push(findings)
                                }
                            }
                        }
                        resolve(scanResults)

                    }).catch((error) => {
                        reject(error)
                    })
                } else {
                    //Do detailed scan as quick scan didn't work
                    nmapScanner.useNmapModule(targetIps + additionalParameters + ' -Pn -T4 -sU', '-sS').then((secondScanData) => {
                        totalHostsUp = secondScanData.length
                        //ARP scan
                        nmapScanner.useNmapModule(targetIps + additionalParameters + portRange, '-PR').then((arpData) => {
                            totalArpHostsUp = arpData.length

                            if (totalArpHostsUp === 0) {
                                for (let j = 0; j < totalHostsUp; j++) {
                                    let findings = { "Host availale via IP : ": secondScanData[j].ip }
                                    scanResults.push(findings)
                                }
                            } else {
                                let arpIps = [] //to exclude form total hosts for IP
                                for (let w = 0; w < totalArpHostsUp; w++) {
                                    arpIps.push(arpData[w].ip)
                                }
                                //add ARP hosts in finding
                                for (let m = 0; m < totalArpHostsUp; m++) {
                                    let findings = { "Host availale via ARP : ": arpData[m].ip }
                                    scanResults.push(findings)
                                }
                                //add IP hosts in findings
                                for (let n = 0; n < totalHostsUp.length; n++) {
                                    if (!arpIps.includes(secondScanData[n].ip)) {
                                        let findings = { "Host availale via IP : ": secondScanData[n].ip }
                                        scanResults.push(findings)
                                    }
                                }
                            }
                            resolve(scanResults)
                        }).catch((error) => {
                            reject(error)
                        })
                    }).catch((error) => {
                        reject(error)
                    })
                }
            }).catch((error) => {
                reject(error)
            })
        })

    }
    return {
        scan: scan,
    }

}