const scanners = require('./scanners/networklayers')
const findingApiAdaptor = require('./adapters/findingsApi')
const apiKey = findingApiAdaptor.config.apiKey
const providerId = findingApiAdaptor.config.providerId
const accountId = findingApiAdaptor.config.accountId
const cardId = findingApiAdaptor.config.cardId
const cardTitle = findingApiAdaptor.config.cardTitle
const applicationLayerFindingsID = findingApiAdaptor.config.findingsId_application
const transportLayerFindingsID = findingApiAdaptor.config.findingsId_transport
const dataLinkLayerFindingsID = findingApiAdaptor.config.findingsId_datalink
const networkLayerFindingsID = findingApiAdaptor.config.findingsId_network

module.exports = exporterFunction

function exporterFunction(logger) {

    logger = logger || console

    function execute(yargs, target, additionalParameters, portRange, securityAdvisorDashboardRegion, updateDashboardCard) {
        yargs.command({
            command: 'applicationLayerScan',
            describe: 'Perform Nmap scans for Application Layer vulnerabilities on targets',
            handler: async function () {
                logger.log("info", "Starting Application layer scan for targets: " + target)
                await scanAndRecordFindings(target, additionalParameters, portRange, scanType = 'applicationLayerScan').catch((error) => {
                    logger.log("error", "Application layer scan failed with error: " + error)
                })
                process.exit()
            }
        })

        yargs.command({
            command: 'transportLayerScan',
            describe: 'Perform Nmap scans for Transport Layer vulnerabilities on targets',
            handler: async function () {
                logger.log("info", "Starting Transport layer scan for targets: " + target)
                await scanAndRecordFindings(target, additionalParameters, portRange, scanType = 'transportLayerScan').catch((error) => {
                    logger.log("error", "Transport layer scan failed with error: " + error)
                })
                process.exit()
            }
        })

        yargs.command({
            command: 'networkLayerScan',
            describe: 'Perform Nmap scans for Network Layer vulnerabilities on targets',
            handler: async function () {
                logger.log("info", "Starting Network layer scan for targets: " + target)
                await scanAndRecordFindings(target, additionalParameters, portRange, scanType = 'networkLayerScan').catch((error) => {
                    logger.log("error", "Network layer scan failed with error: " + error)
                })
                process.exit()
            }
        })

        yargs.command({
            command: 'dataLinkLayerScan',
            describe: 'Perform Nmap scans for Data Link Layer vulnerabilities on targets',
            handler: async function () {
                await scanAndRecordFindings(target, additionalParameters, portRange, scanType = 'dataLinkLayerScan').catch((error) => {
                    logger.log("error", "Data link layer scan failed with error: " + error)
                })

                process.exit()
            }
        })

        yargs.command({
            command: 'allNetworkLayersScan',
            describe: 'Perform Nmap scans for Application, Network, Transport and DataLink Layer vulnerabilities on targets',
            handler: async function () {
                logger.log("info", "Starting Application, Transport, Network and Data link layer scan for targets: " + target)
                await scanAndRecordFindings(target, additionalParameters, portRange, scanType = 'applicationLayerScan').catch((error) => {
                    logger.log("error", "Application layer scan failed with error: " + error)
                })
                await scanAndRecordFindings(target, additionalParameters, portRange, scanType = 'transportLayerScan').catch((error) => {
                    logger.log("error", "Transport layer scan failed with error: " + error)
                })
                await scanAndRecordFindings(target, additionalParameters, portRange, scanType = 'networkLayerScan').catch((error) => {
                    logger.log("error", "Network layer scan failed with error: " + error)
                })
                await scanAndRecordFindings(target, additionalParameters, portRange, scanType = 'dataLinkLayerScan').catch((error) => {
                    logger.log("error", "Data link layer scan failed with error: " + error)
                })

                process.exit()

            }
        })

        yargs.command({
            command: 'deleteCard',
            describe: 'Delete card from Security Advisor\'s Dashboard',
            handler: async function () {
                logger.log("info", "Deleting card \'"+ cardTitle + "\'" + " from region: " + securityAdvisorDashboardRegion )
                await findingApiAdaptor.deleteCard(apiKey, accountId, providerId, securityAdvisorDashboardRegion, cardId, logger).catch((error) => {
                    logger.log("error", "Failed to delete dashboard card")
                    logErrorAndExit(error)
                })
                logger.log("info", "Card deleted at : " + new Date().toISOString().replace(/T/, ' ').replace(/\..+/, ''))
            }
        })

        yargs.parse()
        
        async function scanAndRecordFindings(target, additionalParameters, portRange, scanType) {
            let scanResults = []
            let kpiId = ''
            switch (scanType) {
                case 'applicationLayerScan':
                    scanResults = await scanners.scanApplicationLayer(target, additionalParameters, portRange).catch((error) => {
                        logErrorAndExit(error,"Application layer Nmap scan failed, exiting process now: ")
                    })
                    kpiId = applicationLayerFindingsID
                    break;
                case 'transportLayerScan':
                    scanResults = await scanners.scanTransportLayer(target, additionalParameters, portRange).catch((error) => {
                        logErrorAndExit(error,"Transport layer Nmap scan failed, exiting process now: ")
                    })
                    kpiId = transportLayerFindingsID
                    break;
                case 'networkLayerScan':
                    scanResults = await scanners.scanNetworkLayer(target, additionalParameters, portRange).catch((error) => {
                        logErrorAndExit(error,"Network layer Nmap scan failed, exiting process now: ")
                    })
                    kpiId = networkLayerFindingsID
                    break;
                case 'dataLinkLayerScan':
                    scanResults = await scanners.scanDataLinkLayer(target, additionalParameters, portRange).catch((error) => {
                        logErrorAndExit(error,"Data link layer Nmap scan failed, exiting process now: ")
                    })
                    kpiId = dataLinkLayerFindingsID
                    break;
            }

            if (scanResults.length < 1) {
                logger.log("info", "Scan " + scanType + " is complete, no vulnerabilities found")
            }
            logger.log("debug","Scan results are: " + JSON.stringify(scanResults))
            

            logger.log("debug", "Adding  scan results to Dashboard now")
            await findingApiAdaptor.recordFindings(apiKey, accountId, providerId, securityAdvisorDashboardRegion, cardId, updateDashboardCard, kpiId, scanResults, logger).catch((error) => {
                logger.log("error", "Failed to add findings in Dashboard")
                logErrorAndExit(error)
            })
            
            logger.log("info", scanType + " Scan results added in Security Advisor\'s Dashboard")
            logger.log("info", "Latest " + scanType + " scan completed at : " + new Date().toISOString().replace(/T/, ' ').replace(/\..+/, ''))
        }


        function logErrorAndExit(error,errorMessage) {
            logger.log("error", errorMessage + error)
        }

    }


    return {
        execute: execute,
    }

}