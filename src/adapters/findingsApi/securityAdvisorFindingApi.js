const restClient = require("../../../utils/restClient")();
const templates = require('./templates')
const iamClient = require('../../../utils/IAMClient')
const conf = require('./config')

var exports = module.exports = exportedFunction

const findingSource = conf.config.findingSource
const applicationLayerFindingsID = conf.config.findingsId_application
const transportLayerFindingsID = conf.config.findingsId_transport
const networkLayerFindingsID = conf.config.findingsId_network
const dataLinkLayerFindingsID = conf.config.findingsId_datalink

function exportedFunction() {

    let findingsApiEndPoints = {

        'us-south': 'https://us-south.secadvisor.cloud.ibm.com/findings/v1/',
        'eu-gb': 'https://eu-gb.secadvisor.cloud.ibm.com/findings/v1/'

    }

    async function recordFindings(iamEndpoint, apiKey, accountId, providerId, region, cardId, updateDashboardCard, findingsID, scanResults, logger) {
        let cardStatus = await ifCardExist(iamEndpoint, apiKey, accountId, providerId, cardId, region).catch((err) => { throw err })

        if (cardStatus === 404 || updateDashboardCard === 'yes') {
            if (cardStatus === 404) {
                updateDashboardCard = 'no'
                logger.log("info", "Card not present in dashboard, creating card now")
            } else {
                logger.log("info", "Updating dashboard card now")
            }
            await createOrUpdateCard(iamEndpoint, apiKey, accountId, providerId, region, updateDashboardCard, logger, cardId)
            await createOrUpdateKPIs(iamEndpoint, apiKey, accountId, providerId, region, updateDashboardCard, logger, cardId)
            await createOccurrence(iamEndpoint, apiKey, accountId, providerId, region, scanResults, findingsID, logger)
            return
        }
        logger.log("info", "Card is present, recording occurrences now")
        await createOccurrence(iamEndpoint, apiKey, accountId, providerId, region, scanResults, findingsID, logger)
        return
    }


    async function ifCardExist(iamEndpoint, apiKey, accountId, providerId, cardId, region) {

        const bearerToken = await iamClient.getIamToken(iamEndpoint, apiKey)
        let options = {
            headers: {
                "accept": "application/json",
                "authorization": "Bearer " + bearerToken,
                "content-type": "application/json"
            },
        }

        const urlToVerifyIfCardExist = findingsApiEndPoints[region] + accountId + '/providers/' + providerId + '/notes/' + cardId
        const response = await restClient.call("GET", urlToVerifyIfCardExist, options).catch((err) => { throw "Request to check if card already exists failed " + err })
        return response.statusCode
    }

    //Create card
    async function createOrUpdateCard(iamEndpoint, apiKey, accountId, providerId, region, updateDashboardCard, logger, cardId) {
        //updateCard can be used when need to update card from cli
        const bearerToken = await iamClient.getIamToken(iamEndpoint, apiKey)
        let options = {
            headers: {
                "accept": "application/json",
                "authorization": "Bearer " + bearerToken,
                "content-type": "application/json"
            },
        }

        options.body = JSON.stringify(templates.createNewCardTemplate)

        if (updateDashboardCard === 'yes') {
            logger.log("debug", "Card update in progress")
            let urlToCreateNewCard = findingsApiEndPoints[region] + accountId + '/providers/' + providerId + '/notes/' + cardId
            let response = await restClient.call("PUT", urlToCreateNewCard, options).catch((err) => { throw "Update card request failed " + err })
            logger.log("debug", "Card update request\'s response code is: "+ response.statusCode)
            return
        }

        logger.log("debug", "Card creation in progress")
        let urlToCreateNewCard = findingsApiEndPoints[region] + accountId + '/providers/' + providerId + '/notes'
        let response = await restClient.call("POST", urlToCreateNewCard, options).catch((err) => { throw "Create new card request failed " + err })
        logger.log("debug", "Card creation request\'s response code is: "+ response.statusCode)

        if (response.statusCode === '409') {
            logger.log("debug", "This looks like conflict issue.Please run scan with argument : --updateDashboardCard 'yes' ")
            process.exit()
        }
    }

    //Create Finding
    async function createOrUpdateKPIs(iamEndpoint, apiKey, accountId, providerId, region, updateDashboardCard, logger, cardId) {

        //create a finding for each KPI
        const findingIdsList = [applicationLayerFindingsID, transportLayerFindingsID, networkLayerFindingsID, dataLinkLayerFindingsID]
        const totalKPIs = findingIdsList.length

        for (let i = 0; i < totalKPIs; i++) {

            const findingID = findingIdsList[i]
            const bearerToken = await iamClient.getIamToken(iamEndpoint, apiKey)
            let options = {
                headers: {
                    "accept": "application/json",
                    "authorization": "Bearer " + bearerToken,
                    "content-type": "application/json"
                },
            }
            let createNewFinding = {
                "kind": "FINDING",
                "short_description": "Nmap finding",
                "long_description": "Detail of High vulnerabilities",
                "provider_id": providerId,
                "id": findingID,
                "reported_by": {
                    "id": providerId,
                    "title": findingSource
                },
                "finding": {
                    "severity": "MEDIUM",
                    "next_steps": [
                        {
                            "title": "Learn more about open port risks",
                            "url": "https://nmap.org/book/man-port-scanning-basics.html"
                        }
                    ]
                }
            }


            options.body = JSON.stringify(createNewFinding)
            if (updateDashboardCard === 'yes') {
                logger.log("debug", "Updating KPIs")
                let urlToCreateFinding = findingsApiEndPoints[region] + accountId + "/providers/" + providerId + "/notes/" + findingID
                let response = await restClient.call("PUT", urlToCreateFinding, options).catch((err) => { throw "Update KPIs request failed " + err })
                logger.log("debug", "KPI update request\'s response code is: " + response.statusCode)
                return
            }
            logger.log("debug", "Creating KPIs")
            let urlToCreateFinding = findingsApiEndPoints[region] + accountId + "/providers/" + providerId + "/notes"
            let response = await restClient.call("POST", urlToCreateFinding, options).catch((err) => { throw "CREATE KPIs request failed " + err })
            logger.log("debug", "KPI creation request\'s response code is: "+ response.statusCode)
            if (response.statusCode === '409') {
                logger.log("debug", "This looks like conflict issue.Please run scan with argument : --updateDashboardCard 'yes' ")
            }
        }

    }

    //Create Occurrence
    async function createOccurrence(iamEndpoint, apiKey, accountId, providerId, region, results, findingsID, logger) {

        const totalOccurrences = results.length
        logger.log("debug", "Total occurrence are: ", totalOccurrences)
        for (let i = 0; i < totalOccurrences; i++) {
            logger.log("debug", "Recording occurrence now")
            let targetIp = ''
            let openPortOrProtocol = ''
            let serviceOnPort = ''
            let ipProtocolNumber = ''
            let shortDescription = ''
            let longDescription= ''
            let resourceType = ''


            if (findingsID === 'Nmap-application-layer-findings-type') {

                targetIp = Object.keys(results[i]).toString()
                openPortOrProtocol = Object.values(results[i])[0][0]
                serviceOnPort = Object.values(results[i])[0][1]
                shortDescription = "Open Port: " + openPortOrProtocol + " Service: " + serviceOnPort
                longDescription = "Open ports found in Application Layer"
                resourceType = "Open port in Application layer"

            } else if (findingsID === 'Nmap-transport-layer-findings-type') {

                targetIp = Object.keys(results[i]).toString()
                openPortOrProtocol = Object.values(results[i])[0][0]
                ipProtocolNumber = Object.values(results[i])[0][1]
                shortDescription = "Open Protocol: " + openPortOrProtocol + "   , IP Protocol number: " + ipProtocolNumber
                longDescription = "Hosts available via "+ openPortOrProtocol + " in Transport Layer"
                resourceType = "Open protocol in Transport layer"

            } else if (findingsID === 'Nmap-network-layer-findings-type') {

                targetIp = Object.values(results[i]).toString()
                shortDescription = Object.keys(results[i]).toString() + targetIp
                longDescription = "Hosts available via IP or ARP protocol in Network Layer"
                resourceType = "Hosts available via IP or ARP in Network Layer"

            } else if (findingsID === 'Nmap-datalink-layer-findings-type') {

                targetIp = Object.keys(results[i]).toString()
                openPortOrProtocol = Object.values(results[i])[0][0]
                serviceOnPort = Object.values(results[i])[0][1]
                shortDescription = "Open Port: " + openPortOrProtocol + " Service: " + serviceOnPort
                longDescription = "Hosts available via PPP in Data Link layer"
                resourceType = "Hosts available via PPP in Data Link Layer"

            }


            let createNewOccurrence = {
                "note_name": accountId + "/providers/" + providerId + "/notes/" + findingsID,
                "kind": "FINDING",
                "short_description": shortDescription,
                "long_description": longDescription,
                "remediation": "how to resolve this",
                "provider_id": providerId,
                "id": "occurrence-id" + new Date().getTime(),
                "context": {
                    "resource_name": "Target Host: " + targetIp,
                    "resource_type": resourceType
                },
                "reported_by": {
                    "id": providerId,
                    "title": "Nmap network scan"
                },
                "finding": {
                    "severity": "HIGH",
                    "next_steps": [{
                        "title": "Click for more details on Nmap port scans",
                        "url": "https://nmap.org/book/man-port-scanning-basics.html"
                    }]
                }
            }

            const bearerToken = await iamClient.getIamToken(iamEndpoint, apiKey)
            let options = {
                headers: {
                    "accept": "application/json",
                    "authorization": "Bearer " + bearerToken,
                    "content-type": "application/json"
                },
            }
            urlToCreateOccurrence = findingsApiEndPoints[region] + accountId + "/providers/" + providerId + "/occurrences"
            options.body = JSON.stringify(createNewOccurrence)
            const response = await restClient.call("POST", urlToCreateOccurrence, options).catch((err) => { throw "Post scan findings request to dashboard Failed " + err })
            logger.log("debug", "Occurrence creation request\'s response code is: " + response.statusCode)

        }

    }

    async function deleteCard(iamEndpoint, apiKey, accountId, providerId, region, cardID, logger) {

        const findingIdsList = [applicationLayerFindingsID, transportLayerFindingsID, networkLayerFindingsID, dataLinkLayerFindingsID]
        const totalKPIs = findingIdsList.length

        const bearerToken = await iamClient.getIamToken(iamEndpoint, apiKey)
        var options = {
            headers: {
                "accept": "application/json",
                "authorization": "Bearer " + bearerToken,
            },
        }
        logger.log("info", "Deleting Card and KPIs")

        //Delete all KPI types
        for (let i = 0; i < totalKPIs; i++) {

            let urlToDeleteFinding = findingsApiEndPoints[region] + accountId + "/providers/" + providerId + "/notes/" + findingIdsList[i]
            let response = await restClient.call("DELETE", urlToDeleteFinding, options).catch((err) => { throw "Delete KPI request failed " + err })
            
            if (response.statusCode != 200) {
                logger.log("error", "Delete Card/KPI request failed with response code: " + response.statusCode)
                process.exit(1)
            }
            logger.log("debug", "KPI deletion request is successful, response code is: "+ response.statusCode)

        }

        //Delete Card
        let urlToDeleteCard = findingsApiEndPoints[region] + accountId + "/providers/" + providerId + "/notes/" + cardID
        let response = await restClient.call("DELETE", urlToDeleteCard, options).catch((err) => { throw "Delete Card request failed " + err })
        
        if (response.statusCode != 200) {
            logger.log("error", "Delete Card request failed with response code: " + response.statusCode)
            process.exit(1)
        }
        logger.log("info", "Card deletion request is successful, response code is: "+ response.statusCode)

    }

    return {
        createOrUpdateCard: createOrUpdateCard,
        createOrUpdateKPIs: createOrUpdateKPIs,
        createOccurrence: createOccurrence,
        ifCardExist: ifCardExist,
        recordFindings: recordFindings,
        deleteCard: deleteCard
    }

}
