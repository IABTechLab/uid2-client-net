using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace UID2.Client
{
    internal class Uid2ClientHelper
    {
        private readonly string _endpoint;
        private readonly string _authKey;
        private readonly byte[] _secretKey;

        private readonly HttpClient _client = new HttpClient();

        public Uid2ClientHelper(string endpoint, string authKey, string secretKey)
        {
            _endpoint = endpoint;
            _authKey = authKey;
            _secretKey = Convert.FromBase64String(secretKey);

        }

        internal static string GetAssemblyNameAndVersion()
        {
            var version = ThisAssembly.AssemblyVersion;
            return "uid-client-net-" + version;
        }

        public async Task<(String responseString, HttpStatusCode statusCode)> PostRequest(String urlSuffix)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, _endpoint + urlSuffix);
            request.Headers.Add("Authorization", $"Bearer {_authKey}");
            request.Headers.Add("X-UID2-Client-Version", $"{GetAssemblyNameAndVersion()}");

            var (body, nonce) = V2Helper.MakeEnvelope(_secretKey, DateTime.UtcNow);
            request.Content = new StringContent(body, Encoding.ASCII);

            using (var response = await _client.SendAsync(request, CancellationToken.None).ConfigureAwait(false))
            {
                response.EnsureSuccessStatusCode();
                var responseStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
                using (var reader = new StreamReader(responseStream))
                {
                    var responseBody = await reader.ReadToEndAsync().ConfigureAwait(false);
                    var responseBytes = V2Helper.ParseResponse(responseBody, _secretKey, nonce);
                    var responseString = Encoding.UTF8.GetString(responseBytes);
                    return (responseString, response.StatusCode);
                }
            }
        }
    }
}
