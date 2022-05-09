// Copyright (c) 2021 The Trade Desk, Inc
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Net;
using System.Net.Http;
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
        
        public DecryptionResponse Decrypt(string token, DateTime now)
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
                return UID2Encryption.Decrypt(Convert.FromBase64String(token), container, now, _identityScope);
            }
            catch (Exception)
            {
                return DecryptionResponse.MakeError(DecryptionStatus.InvalidPayload);
            }
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

        private async Task<RefreshResponse> RefreshInternal(CancellationToken token)
        {
            var request = new HttpRequestMessage(RefreshHttpMethod, _endpoint + "/v2/key/latest");
            request.Headers.Add("Authorization", $"Bearer {_authKey}");
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
                        var json = V2Helper.ParseResponse(responseBody, _secretKey, nonce);
                        Volatile.Write(ref _container, KeyParser.Parse(json));
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