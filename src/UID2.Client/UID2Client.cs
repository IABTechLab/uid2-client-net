using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Reflection; //Assembly.GetEntryAssembly()
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace UID2.Client
{
    internal class UID2Client : IUID2Client
    {
        public static readonly HttpMethod RefreshHttpMethod = HttpMethod.Post;

        private readonly string _endpoint;
        private readonly string _authKey;
        private readonly byte[] _secretKey;
        private readonly IdentityScope _identityScope;

        private readonly HttpClient _client;

        private KeyContainer _container;


        public UID2Client(string endpoint, string authKey, string secretKey, IdentityScope identityScope)
        {
            _client = new HttpClient();
            _endpoint = endpoint;
            _authKey = authKey;
            _secretKey = Convert.FromBase64String(secretKey);
            _identityScope = identityScope;
        }

        public DecryptionResponse Decrypt(string token)
        {
            return Decrypt(token, DateTime.UtcNow, expectedDomainName: null);
        }

        public DecryptionResponse Decrypt(string token, DateTime utcNow)
        {
            return Decrypt(token, utcNow, expectedDomainName: null);
        }

        public DecryptionResponse Decrypt(string token, string expectedDomainName)
        {
            return Decrypt(token, DateTime.UtcNow, expectedDomainName);
        }

        public DecryptionResponse Decrypt(string token, DateTime now, string expectedDomainName)
        {
            var container = Volatile.Read(ref _container);
            if (container == null)
            {
                return DecryptionResponse.MakeError(DecryptionStatus.NotInitialized);
            }

            if (!container.IsValid(now))
            {
                return DecryptionResponse.MakeError(DecryptionStatus.KeysNotSynced);
            }

            try
            {
                return UID2Encryption.Decrypt(token, container, now, expectedDomainName, _identityScope);
            }
            catch (Exception)
            {
                return DecryptionResponse.MakeError(DecryptionStatus.InvalidPayload);
            }
        }

        public EncryptionDataResponse Encrypt(string rawUid)
        {
            return Encrypt(rawUid, DateTime.UtcNow);
        }

        internal EncryptionDataResponse Encrypt(string rawUid, DateTime now)
        {
            return UID2Encryption.Encrypt(rawUid, Volatile.Read(ref _container), _identityScope, now);
        }


        public EncryptionDataResponse EncryptData(EncryptionDataRequest request)
        {
            return UID2Encryption.EncryptData(request, Volatile.Read(ref _container), _identityScope);
        }

        public DecryptionDataResponse DecryptData(String encryptedData)
        {
            var container = Volatile.Read(ref _container);
            if (container == null)
            {
                return DecryptionDataResponse.MakeError(DecryptionStatus.NotInitialized);
            }

            if (!container.IsValid(DateTime.UtcNow))
            {
                return DecryptionDataResponse.MakeError(DecryptionStatus.KeysNotSynced);
            }

            try
            {
                return UID2Encryption.DecryptData(Convert.FromBase64String(encryptedData), container, _identityScope);
            }
            catch (Exception)
            {
                return DecryptionDataResponse.MakeError(DecryptionStatus.InvalidPayload);
            }
        }

        public RefreshResponse Refresh()
        {
            return RefreshInternal(CancellationToken.None).Result;
        }

        public RefreshResponse RefreshJson(string json)
        {
            try
            {
                Volatile.Write(ref _container, KeyParser.Parse(json));
                return RefreshResponse.MakeSuccess();
            }
            catch (Exception e)
            {
                return RefreshResponse.MakeError(e.Message);
            }
        }

        public async Task<RefreshResponse> RefreshAsync(CancellationToken token)
        {
            return await RefreshInternal(token).ConfigureAwait(false);
        }

        private string GetAssemblyNameAndVersion()
        {
            var version = "5.4.0";
            return "uid-client-net-" + version;
        }

        private async Task<RefreshResponse> RefreshInternal(CancellationToken token)
        {
            var request = new HttpRequestMessage(RefreshHttpMethod, _endpoint + "/v2/key/sharing");
            request.Headers.Add("Authorization", $"Bearer {_authKey}");
            request.Headers.Add("X-UID2-Client-Version", $"{GetAssemblyNameAndVersion()}");
            HttpStatusCode? statusCode = null;
            try
            {
                var (body, nonce) = V2Helper.MakeEnvelope(_secretKey, DateTime.UtcNow);
                request.Content = new StringContent(body, Encoding.ASCII);

                using (var response = await _client.SendAsync(request, token).ConfigureAwait(false))
                {
                    statusCode = response.StatusCode;
                    response.EnsureSuccessStatusCode();
                    var responseStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
                    using (var reader = new StreamReader(responseStream))
                    {
                        var responseBody = await reader.ReadToEndAsync().ConfigureAwait(false);
                        var responseBytes = V2Helper.ParseResponse(responseBody, _secretKey, nonce);
                        Volatile.Write(ref _container, KeyParser.Parse(Encoding.UTF8.GetString(responseBytes)));
                    }
                    return RefreshResponse.MakeSuccess();
                }
            }
            catch (HttpRequestException webEx)
            {
                return RefreshResponse.MakeError($"Web error: HttpStatus={statusCode}, {webEx.Message}");
            }
            catch (Exception parserEx)
            {
                return RefreshResponse.MakeError(parserEx.Message);
            }
        }
    }
}
