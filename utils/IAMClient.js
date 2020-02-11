const rest = require("./restClient")();

async function getIamToken(iamTokenUrl, apikey){
    let options = {
        headers: {
            "authorization" : "Basic Yng6Yng=",
            "content-type" : "application/x-www-form-urlencoded"
        },
        form:{
            grant_type: "urn:ibm:params:oauth:grant-type:apikey",
            apikey: apikey,
            response_type: "cloud_iam",
            
        }
    }
    const response = await rest.call("POST", iamTokenUrl, options).catch((err)=>{throw Error("IAM token retrieval failed " + err)})
    const tokens = JSON.parse(response.body)
    return tokens.access_token
    
}

module.exports.getIamToken = getIamToken
