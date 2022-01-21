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

using System;
using System.Threading;
using System.Threading.Tasks;

namespace UID2.Client
{
    /// <summary>
    /// Client for interacting with UID2 services.
    /// </summary>
    public interface IUID2Client
    {
        /// <summary>
        /// This will synchronously connect to the corresponding UID2 service and fetch the latest
        /// set of encryption keys which can then be used to decrypt advertising tokens using
        /// the decrypt_token function.
        /// </summary>
        /// <returns>Response indicating whether the refresh is successful or not</returns>
        RefreshResponse Refresh();

        /// <summary>
        /// Load the keys in the param json into the client
        /// </summary>
        /// <param name="json"></param>
        /// <returns>a response indicating if the refresh is successful</returns>
        RefreshResponse RefreshJson(string json);

        Task<RefreshResponse> RefreshAsync(CancellationToken token);

        /// <summary>
        /// Decrypt advertising token to extract UID2 details.
        /// </summary>
        /// <param name="token">The UID2 Token </param>
        /// <param name="now">At what time this token is being decrypted</param>
        /// <returns>Response showing if decryption is successful and the resulting UID if successful.
        /// Or it could return error codes/string indicating what went wrong
        /// </returns>
        DecryptionResponse Decrypt(string token, DateTime now);

        EncryptionDataResponse EncryptData(EncryptionDataRequest request);

        DecryptionDataResponse DecryptData(string encryptedData);
    }

    public class UID2ClientFactory
    {
        public static IUID2Client Create(string endpoint, string authKey)
        {
            return new UID2Client(endpoint, authKey);
        }
    }
}
