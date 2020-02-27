const restClient = require("../../../utils/restClient")();
const templates = require('./templates')
const iamClient = require('../../../utils/IAMClient')
const conf = require('./config')
const findingApi = require('ibm-security-advisor/findings-api/v1')
const {BearerTokenAuthenticator} = require('ibm-security-advisor/auth')

var exports = module.exports = exportedFunction

const findingSource = conf.config.findingSource
const applicationLayerFindingsID = conf.config.findingsId_application
const transportLayerFindingsID = conf.config.findingsId_transport
const networkLayerFindingsID = conf.config.findingsId_network
const dataLinkLayerFindingsID = conf.config.findingsId_datalink

function exportedFunction() {

    let findingsApiEndPoints = {

        'us-south': 'https://us-south.secadvisor.cloud.ibm.com/findings',
        'eu-gb': 'https://eu-gb.secadvisor.cloud.ibm.com/findings'

    }

    async function recordFindings(iamEndpoint, apiKey, accountId, providerId, region, cardId, updateDashboardCard, findingsID, scanResults, logger) {
        let cardStatus = await ifCardExist(iamEndpoint, apiKey, accountId, providerId, cardId, region).catch((err) => { throw(err) })
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
        const client = new findingApi({
            serviceUrl: findingsApiEndPoints[region],
            authenticator: new BearerTokenAuthenticator({
                bearerToken: bearerToken
            })
        })
        let response = await client.getNote({
            accountId: accountId,
            providerId: providerId,
            noteId: cardId
        }).catch(err => { if(err.code === 404){ return err.code } else{ throw(err) }
        }).then(resp => { return resp })
        return response
    }

    //Create card
    async function createOrUpdateCard(iamEndpoint, apiKey, accountId, providerId, region, updateDashboardCard, logger, cardId) {
        //updateCard can be used when need to update card from cli
        
        const bearerToken = await iamClient.getIamToken(iamEndpoint, apiKey)
        const client = new findingApi({
            serviceUrl: findingsApiEndPoints[region],
            authenticator: new BearerTokenAuthenticator({
                bearerToken: bearerToken
            })
        })
        let body = templates.createNewCardTemplate
        if (updateDashboardCard === 'yes') {
            logger.log("debug", "Card update in progress")
            let response = await client.updateNote({
                accountId: accountId,
                providerId: providerId,
                shortDescription: body.short_description,
                longDescription: body.long_description,
                kind: body.kind,
                noteId: body.id,
                id: body.id,
                reportedBy: body.reported_by,
                card: body.card
            }).catch(err => { throw(err) })
            logger.log("debug", "Card update request\'s response code is: "+ response.status)
            return
        }
        logger.log("debug", "Card creation in progress")
        let response = await client.createNote({
            accountId: accountId,
            providerId: providerId,
            shortDescription: body.short_description,
            longDescription: body.long_description,
            kind: body.kind,
            id: body.id,
            reportedBy: body.reported_by,
            card: body.card
        }).catch(err => { throw(err) })
        logger.log("debug", "Card creation request\'s response code is: "+ response.status)

        if (response.status === '409') {
            logger.log("debug", "This looks like conflict issue.Please run scan with argument : --updateDashboardCard 'yes' ")
            process.exit()
        }
    }

    //Create Finding
    async function createOrUpdateKPIs(iamEndpoint, apiKey, accountId, providerId, region, updateDashboardCard, logger, cardId) {

        //create a finding for each KPI
        const findingIdsList = [applicationLayerFindingsID, transportLayerFindingsID, networkLayerFindingsID, dataLinkLayerFindingsID]
        const bearerToken = await iamClient.getIamToken(iamEndpoint, apiKey)
        const client = new findingApi({
            serviceUrl: findingsApiEndPoints[region],
            authenticator: new BearerTokenAuthenticator({
                bearerToken: bearerToken
            })
        })
        findingIdsList.forEach(async findingID => {
            let body = {
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

            if (updateDashboardCard === 'yes') {
                logger.log("debug", "Updating KPIs")
                let response = client.updateNote({
                    accountId: accountId,
                    providerId: providerId,
                    shortDescription: body.short_description,
                    longDescription: body.long_description,
                    kind: body.kind,
                    noteId: body.id,
                    id: body.id,
                    reportedBy: body.reported_by,
                    finding: body.finding
                }).catch(err => { throw "UPDATE KPIs request failed "+err })
                logger.log("debug", "KPI update request\'s response code is: " + response.status)
                return
            }
            logger.log("debug", "Creating KPIs")
            let response = await client.createNote({
                accountId: accountId,
                providerId: providerId,
                shortDescription: body.short_description,
                longDescription: body.long_description,
                kind: body.kind,
                id: body.id,
                reportedBy: body.reported_by,
                finding: body.finding
            }).catch(err => { throw "CREATE KPIs request failed "+err })
            logger.log("debug", "KPI creation request\'s response code is: "+ response.status)
            if (response.status === '409') {
                logger.log("debug", "This looks like conflict issue.Please run scan with argument : --updateDashboardCard 'yes' ")
            }
        })

    }

    //Create Occurrence
    async function createOccurrence(iamEndpoint, apiKey, accountId, providerId, region, results, findingsID, logger) {
        logger.log("debug", `Total occurrence are: ${results.length}`)
        const bearerToken = await iamClient.getIamToken(iamEndpoint, apiKey)
        const client = new findingApi({
            serviceUrl: findingsApiEndPoints[region],
            authenticator: new BearerTokenAuthenticator({
                bearerToken: bearerToken
            })
        })
        results.forEach(async occurrence => {
            logger.log("debug", "Recording occurrence now")
            let targetIp = ''
            let openPortOrProtocol = ''
            let serviceOnPort = ''
            let ipProtocolNumber = ''
            let shortDescription = ''
            let longDescription= ''
            let resourceType = ''


            if (findingsID === 'Nmap-application-layer-findings-type') {

                targetIp = Object.keys(occurrence).toString()
                openPortOrProtocol = Object.values(occurrence)[0][0]
                serviceOnPort = Object.values(occurrence)[0][1]
                shortDescription = "Open Port: " + openPortOrProtocol + " Service: " + serviceOnPort
                longDescription = "Open ports found in Application Layer"
                resourceType = "Open port in Application layer"

            } else if (findingsID === 'Nmap-transport-layer-findings-type') {

                targetIp = Object.keys(occurrence).toString()
                openPortOrProtocol = Object.values(occurrence)[0][0]
                ipProtocolNumber = Object.values(occurrence)[0][1]
                shortDescription = "Open Protocol: " + openPortOrProtocol + "   , IP Protocol number: " + ipProtocolNumber
                longDescription = "Hosts available via "+ openPortOrProtocol + " in Transport Layer"
                resourceType = "Open protocol in Transport layer"

            } else if (findingsID === 'Nmap-network-layer-findings-type') {

                targetIp = Object.values(occurrence).toString()
                shortDescription = Object.keys(occurrence).toString() + targetIp
                longDescription = "Hosts available via IP or ARP protocol in Network Layer"
                resourceType = "Hosts available via IP or ARP in Network Layer"

            } else if (findingsID === 'Nmap-datalink-layer-findings-type') {

                targetIp = Object.keys(occurrence).toString()
                openPortOrProtocol = Object.values(occurrence)[0][0]
                serviceOnPort = Object.values(occurrence)[0][1]
                shortDescription = "Open Port: " + openPortOrProtocol + " Service: " + serviceOnPort
                longDescription = "Hosts available via PPP in Data Link layer"
                resourceType = "Hosts available via PPP in Data Link Layer"

            }

            let body = {
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

            let response = await client.createOccurrence({
                accountId: accountId,
                noteName: body.note_name,
                kind: body.kind,
                shortDescription: body.short_description,
                longDescription: body.long_description,
                remediation: body.remediation,
                providerId: body.provider_id,
                id: body.id,
                context: body.context,
                reportedBy: body.reported_by,
                finding: body.finding
            }).catch(err => { throw "CREATE Occurrences request failed "+err })
            logger.log("debug", "Occurrence creation request\'s response code is: " + response.status)

        })

    }

    async function deleteCard(iamEndpoint, apiKey, accountId, providerId, region, cardID, logger) {

        const findingIdsList = [applicationLayerFindingsID, transportLayerFindingsID, networkLayerFindingsID, dataLinkLayerFindingsID]
        const bearerToken = await iamClient.getIamToken(iamEndpoint, apiKey)
        const client = new findingApi({
            serviceUrl: findingsApiEndPoints[region],
            authenticator: new BearerTokenAuthenticator({
                bearerToken: bearerToken
            })
        })
        logger.log("info", "Deleting Card and KPIs")

        //Delete all KPI types
        findingIdsList.forEach(async note => {
            
            let response = await client.deleteNote({
                accountId: accountId,
                providerId: providerId,
                noteId: note
            }).catch(err => { throw "DELETE KPIs request failed "+err })
            if (response.status != 200) {
                logger.log("error", "Delete Card/KPI request failed with response code: " + response.status)
                process.exit(1)
            }
            logger.log("debug", "KPI deletion request is successful, response code is: "+ response.status)

        })

        //Delete Card
        let response = await client.deleteNote({
            accountId: accountId,
            providerId: providerId,
            noteId: cardID
        }).catch(err => { throw "DELETE Card request failed "+err })
        if (response.status != 200) {
            logger.log("error", "Delete Card request failed with response code: " + response.status)
            process.exit(1)
        }
        logger.log("info", "Card deletion request is successful, response code is: "+ response.status)

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
