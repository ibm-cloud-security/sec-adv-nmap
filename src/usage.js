const { spawn } = require('child_process');


module.exports = exporterFunction

function exporterFunction(logger) {

    var logger = logger || console

    function recieveOptions(yargs) {
        yargs.version('0.1')

        yargs.command('$0', 'nmap command must be available', () => { }, (argv) => {
            ifCommandExist('nmap')
        }).usage('Usage:node $0 <command> [options]')
            .example("$0 applicationLayerScan -t \'127.0.0.1 www.google.com\' -p 20-100 --excludePorts 21-22")
            .help('h')
            .alias('h', 'help')

        yargs.option('t', {
            desc: 'Target ip\'s or host names',
            alias: 'targetIPs'
        }).option('p', {
            desc: 'Port range to be scanned, default is all ports',
            alias: 'targetPorts'
        }).option('excludePorts', {
            desc: 'Port range to be excluded eg. 90-100',
        }).option('updateDashboardCard', {
            desc: 'update new card metadata in Dashboard',
        })

        yargs.parse()
    }

    function ifCommandExist(command) {

        logger.log("info", "verifying if " + command + " command is available");
        const ifCmdExists = spawn(command, ["--version"]);

        ifCmdExists.stderr.on('data', (data) => {
            logger.log("error", "Scans could not be initiated. Please make sure Nmap command is available in system\'s path");
            process.exit(1)
        });

        ifCmdExists.on('close', (code) => {
            logger.log("info", "Prerequisite check complete, Nmap command is available");
        });
    }

    return {
        recieveOptions: recieveOptions
    }
}



