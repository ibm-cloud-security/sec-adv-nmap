const rest = require("./restClient")();
const {IamTokenManager} = require("ibm-security-advisor/auth");

async function getIamToken(iamTokenUrl, apikey){
    const authClient = new IamTokenManager({
        apikey: apikey,
        url: iamTokenUrl
    });
    let token = await authClient.requestToken();
    return token['result']['access_token'];
}

module.exports.getIamToken = getIamToken
