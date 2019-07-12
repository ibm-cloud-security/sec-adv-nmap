//Initialize the logger.

module.exports = {

    initLogger: function(testcaseName, logDir) {
        var winston = require('winston');
        var customLevels = {
            levels: {
                debug: 0,
                info: 1,
                warn: 2,
                error: 3
            },
            colors: {
                debug: 'blue',
                info: 'green',
                warn: 'yellow',
                error: 'red'
            }
        };
        var currentLogDir = __dirname + "/../log/"
        var fileName = currentLogDir + "/" + testcaseName + '.log';
        var logger = new(winston.createLogger)({
            transports: [new(winston.transports.Console)(),
                new(winston.transports.File)({
                    filename: fileName,
                    timestamp: function() {
                        var d = new Date();
                        var yyyy = d.getFullYear();
                        var mm = d.getMonth();
                        var dd = d.getDate();
                        var hh = d.getHours();
                        var min = d.getMinutes();
                        var sec = d.getSeconds();
                        var ms = d.getMilliseconds();
                        if (dd < 10) {
                            dd = '0' + dd;
                        }
                        if (mm < 10) {
                            mm = '0' + mm;
                        }
                        var yyyymmddhhss = yyyy + ':' + mm + ':' + dd + ':' + hh + ':' + min + ':' + sec + ':' + ms;
                        return yyyymmddhhss
                    },
                    levels: customLevels.levels,
                    colors: customLevels.colors,
                    json: false,
                    level: process.env.LOG_LEVEL && process.env.LOG_LEVEL.toLowerCase() || "info" ,
                    colorize: true
                })
            ]
        });


        return logger;
    },

}
