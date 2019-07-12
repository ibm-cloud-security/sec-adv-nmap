//nmap must be installed on system and nmap command must be available form commandline

var nmap = require('node-nmap');


module.exports.useNmapModule = useNmapModule

function useNmapModule(targetIpAndParameters, scanType) {

  let nmapscan = new nmap.NmapScan(targetIpAndParameters, scanType);

  return new Promise((resolve, reject) => {
    nmapscan.on('complete', function (data) {
      resolve(data)
    });
    nmapscan.on('error', function (error) {
      console.log(error);
      reject(error)
    });

    nmapscan.startScan();
  })
}



