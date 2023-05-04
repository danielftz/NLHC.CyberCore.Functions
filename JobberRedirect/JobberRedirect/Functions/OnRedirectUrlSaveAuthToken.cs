using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using System;

namespace NLHCCyberCoreFunctions.Functions
{
    public static class OnRedirectUrlSaveAuthToken
    {
        //TODO: better way of passing state parameter. this is temporary
        //this value will be coming from Azure secure storage
        private static string State = "0123456789";


        [FunctionName(nameof(OnRedirectUrlSaveAuthToken))]
        public static IActionResult Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = "RedirectForAuth")] HttpRequest req,
            ILogger log)
        {
            log.LogInformation($"{DateTime.Now}: Jobber has responded to a request to provide authorization code");

            string state = req.Query["state"];

            if (state == State)
            {
                string authCode = req.Query["code"];
                return new OkObjectResult(authCode);
            }

            // return a result indicating that the state parameter was not correct
            return new BadRequestObjectResult("State parameter was not correct");

        }
    }
}
