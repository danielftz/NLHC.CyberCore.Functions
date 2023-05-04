using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;

namespace NLHCCyberCoreFunctions.Functions
{
    public static class OnRedirectUrlSaveAuthToken
    {
        [FunctionName(nameof(OnRedirectUrlSaveAuthToken))]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = "RedirectForAuth")] HttpRequest req,
            ILogger log)
        {
            log.LogInformation($"{DateTime.Now}: Jobber has responded to a request to provide authorization code");

            string keyVaultUrl = "https://nlhccybercoreapisecrets.vault.azure.net/";
            SecretClient client = new(new Uri(keyVaultUrl), new DefaultAzureCredential());
            Response<KeyVaultSecret> stateSecret = await client.GetSecretAsync("jobberState");

            try
            {
                string storedState = stateSecret.Value.Value;

                string providedState = req.Query["state"];

                if (storedState == providedState)
                {
                    string authCode = req.Query["code"];

                    KeyVaultSecret storedAuthCode = new ("jobberAuthorizationCode", authCode);
                    await client.SetSecretAsync(storedAuthCode);

                    return new OkObjectResult("Success");
                }

                // return a result indicating that the state parameter was not correct
                return new BadRequestObjectResult("State parameter was not correct");
            }
            catch
            {
                // return bad request indicating the request was not correct
                return new BadRequestObjectResult("Bad request");

            }
           

        }
    }
}
