const logInfo = require('../utils/logger')
var logger = logInfo.initLogger('NetworkLayers_NmapScan');
const yargs = require('yargs')
var usage = require('./usage.js')(logger)
var commands = require('./commands.js')(logger)

const target = yargs.argv.t || 'localhost'
const securityAdvisorDashboardRegion = process.env.region || 'us-south'

let excludedPorts = ""
let additionalParameters = ''
let portRange = ''
let updateDashboardCard = 'no'

//validate if accountID and apiKey are present
let accountID = process.env.accountID 
let apiKey = process.env.apiKey

let isRequiredValueMissing = false
if(!accountID){
    logger.log("error","IBM Cloud Account ID is missing or has empty value")
    isRequiredValueMissing = true
}
if (!apiKey) {
    logger.log("error","IBM Cloud API key is missing or has empty value")
    isRequiredValueMissing = true
}
if(isRequiredValueMissing){
  process.exit(1)
}


if (yargs.argv.updateDashboardCard === 'yes') {
    updateDashboardCard = 'yes'
}

if (yargs.argv.excludePorts) {
    excludedPorts = " --exclude-ports " + yargs.argv.excludePorts
    additionalParameters = additionalParameters + excludedPorts
}

if (yargs.argv.p) {
    portRange = ' -p ' + yargs.argv.p
}

usage.recieveOptions(yargs)
commands.execute(yargs, target, additionalParameters, portRange, securityAdvisorDashboardRegion, updateDashboardCard)


