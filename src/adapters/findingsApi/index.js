exports.config = require('./config').config
exports.recordFindings = require('./securityAdvisorFindingApi')().recordFindings
exports.deleteCard = require('./securityAdvisorFindingApi')().deleteCard
exports.templates = require('./templates')