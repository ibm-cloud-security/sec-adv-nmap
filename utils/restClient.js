var request = require("request");

var exports = (module.exports = exportedFunction);

function exportedFunction(logger) {
  logger = logger || console;

  function restCall(operation, url, options) {
    options = options || {};
    options.url = url;
    options.method = operation;
    //logger.debug(operation, url, options);
    var promise = new Promise(function(resolve, reject) {
      request(options, function(error, response, body) {
        if (error) {
          logger.debug("error", error);
          reject(new Error("Error during rest operation " + error));
        }else {
          resolve(response);
        }
      });
    });
    return promise;
  }
  return {
    call: restCall
  };
}