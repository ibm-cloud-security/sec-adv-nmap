# DEPRECATED

# Prerequisites :  
1. Nmap must be installed and `nmap` command must be available in system's path.  
   Nmap can be installed from : https://nmap.org/download.html
2. Nodejs must be installed and `node`command must be available in system's path.  
   Download nodejs from : https://nodejs.org/en/download/
3. OS : This application is dependent on Nodejs and Nmap and can be used on Windows,MacOS and other linux distributions.
4. Obtain your IBM Cloud Account ID :  
   To get Account ID from your IBM Cloud account via web browser:  
       Login in to you IBM Cloud account from web browser of your choice.
       Click `Manage` from top bar and then click `Account`  
       CLick `Account settings` from left navigation bar, you can find your Account's ID under title Account
5. Generating API key:  
       Login in to your IBM Cloud account
       Click `Manage` from top bar and then click `Access(IAM)`  
       Click `IBM Cloud API Keys` from left navigation bar  
       Then click `Create an IBM Cloud API key` button. Provide Name and Description of your choice and click create  
       You can then copy  or download your API key.

# Steps to generate and record Nmap findings in Security Advisor's Dashboard:
1. Clone this repository.
2. Run `npm install` at project root to install dependencies.
3. Set  following environment variables :   
  `apiKey` : `This is your IBM Security Advisor account's apikey`  
  `accountID` : `This is your IBM Security Advisor account id`   
  `region` : `This is your IBM Security Advisor account region. Default is us-south`  
5. ### Running a scan :   
   From root directory of repository, run following command for windows   
   `node ./src/app.js <scan_type> -t <IPv4 address>`   
     
   Note : For MacOS/OSX and unix systems root privileges may be required, you can append command with `sudo -E `. Eg. `sudo -E node ./src/app.js <scan_type> -t <IPv4 address>`   
   More information for need of root access to run scans can be found at: https://nmap.org/book/man-port-scanning-techniques.html    
     
    Replace <scan_type> with one of following :   
   `allNetworkLayersScan` : `For scanning all four layers`  
   `applicationLayerScan` : `For Application Layer scan`  
   `transportLayerScan` : `For Transport layer scan`  
   `networkLayerScan` : `For Network layer scan`  
   `dataLinkLayerScan` : `For Data link layer scan`  
   Note : IPv6  and IP ranges are currently not supported.    
6. To Specify a port range to be scanned instead of all ports use `-p` flag:  
   E.g. `node ./src/app.js <scan_type> -t <IPv4 address> -p 0-2000`  
   NOTE : port range i.e `-p` should not be used when running following scan : allNetworkLayersScan, transportLayerScan, networkLayerScan
7. To exclude specific port range from scan use `--excludePorts` flag:  
   E.g. `node ./src/app.js <scan_type> -t <IPv4 address> --excludePorts 90-100`  
   NOTE : `--excludePorts` should not be used when running following scan : allNetworkLayersScan, transportLayerScan, networkLayerScan  

### Duration of visibility of scan alerts in Security Advisor's Dashboard card:   
Scan alerts recorded in Dashboard card are visible for duration of 24 hours in card and after that can be found in Findings table.  
Also, note that if you run scan again within 24 hours of first scan and same findings are found then they will be added in Card.
E.g. You ran Application layer scan which recorded finding as open port 22/ssh it will show as '1' in Application Layer KPI in card.  
     Now, if you run same scan again without fixing above existing vulnerability within 24 hours , it will add finding to Card again and now count for Application Layer will be 2 although same port is still open and no other.
Therefore, if you want to run scan again within 24 hours and see only latest vulnerabilities, please clear findings in card using standard Findings API methods via swagger docs or postman etc.  

### Updating dashboard card:      
 Section name,Card title and card subtitle can be changed by supplying new values in respective fields in <project_root>/src/adapters/findingsApi/config.js file. Default values are : 
 ```
   "sectionName": 'Network',
   "cardId" : 'network-scan-nmap-Card',
   "cardTitle" : 'Port Discovery',
 ```
After making the change run tests with flag `--updateDashboardCard` set to yes.
Eg.`node ./src/app.js <scan_type> -t <IPv4 address> --updateDashboardCard 'yes'`

### Deleting Card from Security Advisor\'s Dashboard:      
Nmap findings card created by this utility can be deleted using following command :   
`node ./src/app.js deleteCard`
