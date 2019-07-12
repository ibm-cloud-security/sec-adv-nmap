exports.scanApplicationLayer = require('./applicationLayerScanner')().scan
exports.scanTransportLayer = require('./transportLayerScanner')().scan
exports.scanNetworkLayer = require('./networkLayerScanner')().scan
exports.scanDataLinkLayer = require('./dataLinkLayerScanner')().scan