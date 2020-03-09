const conf = require('./config')


const providerId = conf.config.providerId
const cardId = conf.config.cardId
const cardTitle = conf.config.cardTitle
const cardSubTitle = conf.config.cardSubTitle
const findingsId_application = conf.config.findingsId_application
const findingsId_transport = conf.config.findingsId_transport
const findingsId_network = conf.config.findingsId_network
const findingsId_datalink = conf.config.findingsId_datalink
const sectionName = conf.config.sectionName

//Template for nmap findings card
var createNewCardTemplate = {

  "kind": "CARD",
  "provider_id": providerId,
  "id": cardId,
  "short_description": "Security risk found by Nmap",
  "long_description": "Details about security risks found by Nmap scan",
  "reported_by": {
    "id": providerId,
    "title": cardTitle
  },
  "card": {
    "section": sectionName,
    "title": cardTitle,
    "subtitle": cardSubTitle,
    "finding_note_names": [
      "providers/" + providerId + "/notes/" + findingsId_application,
      "providers/" + providerId + "/notes/" + findingsId_transport,
      "providers/" + providerId + "/notes/" + findingsId_network,
      "providers/" + providerId + "/notes/" + findingsId_datalink
    ],
    "elements": [
      {
        "kind": "NUMERIC",
        "text": "Application Layer",
        "default_time_range": "1d",
        "value_type": {
          "kind": "FINDING_COUNT",
          "finding_note_names": [
            "providers/" + providerId + "/notes/" + findingsId_application
          ]
        }
      }, {
        "kind": "NUMERIC",
        "text": "Transport Layer",
        "default_time_range": "1d",
        "value_type": {
          "kind": "FINDING_COUNT",
          "finding_note_names": [
            "providers/" + providerId + "/notes/" + findingsId_transport
          ]
        }
      }, {
        "kind": "NUMERIC",
        "text": "Network Layer",
        "default_time_range": "1d",
        "value_type": {
          "kind": "FINDING_COUNT",
          "finding_note_names": [
            "providers/" + providerId + "/notes/" + findingsId_network
          ]
        }
      }, {
        "kind": "NUMERIC",
        "text": "Data Link Layer",
        "default_time_range": "1d",
        "value_type": {
          "kind": "FINDING_COUNT",
          "finding_note_names": [
            "providers/" + providerId + "/notes/" + findingsId_datalink
          ]
        }
      }
    ]
  }
}


module.exports.createNewCardTemplate = createNewCardTemplate
