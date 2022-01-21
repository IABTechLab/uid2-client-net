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
using System.IO;
using System.Security.Cryptography;
using System.Text;
using UID2.Client.Utils;

namespace UID2.Client.Test.Utils
{
    /// <summary>
    /// Utility class to generate UID2 Token, this should be used for testing
    /// bid request handling logic to ensure it could decrypt the raw UID2 from the UID2 Token provided
    /// by SSPs/publishers. Production system should not need this.
    /// </summary>
    public static class UID2TokenGenerator
    {
        public class Params
        {
            public DateTime TokenExpiry = DateTime.UtcNow.AddHours(1);

            public Params() { }
            public Params WithTokenExpiry(DateTime expiry) { TokenExpiry = expiry; return this; }
        }

        public static Params DefaultParams => new Params();

        public static string GenerateUID2Token(string uid, Key masterKey, int siteId, Key siteKey)
        {
            return GenerateUID2Token(uid, masterKey, siteId, siteKey, DefaultParams);
        }
        
        /// <summary>
        ///  The data can be decrypted with UID2.Client.IUID2Client.Decrypt method
        /// </summary>
        /// <param name="uid">UID to be encrypted to a UID2 Token</param>
        /// <param name="masterKey">The mandatory key that is not site-specific and would encrypt UID into a UID2 Token</param>
        /// <param name="siteId">The unique identifier of the publisher</param>
        /// <param name="siteKey">site-specific key to encrypt the UID with first before encrypting again with master key</param>
        /// <param name="encryptParams"></param>
        /// <returns>the encrypted UID in the form of UID2 Token</returns>
        public static string GenerateUID2Token(string uid, Key masterKey, int siteId, Key siteKey, Params encryptParams)
        {
            var uidBytes = Encoding.UTF8.GetBytes(uid);
            var identityStream = new MemoryStream();
            var identityWriter = new BigEndianByteWriter(identityStream);
            identityWriter.Write(siteId);
            identityWriter.Write(uidBytes.Length);
            identityWriter.Write(uidBytes);
            identityWriter.Write(0);
            identityWriter.Write(DateTimeUtils.DateTimeToEpochMilliseconds(DateTime.UtcNow.AddHours(-1)));
            byte[] identityIv = new byte[16];
            ThreadSafeRandom.PerThread.NextBytes(identityIv);
            byte[] encryptedIdentity = Encrypt(identityStream.ToArray(), identityIv, siteKey.Secret);

            var masterStream = new MemoryStream();
            var masterWriter = new BigEndianByteWriter(masterStream);
            masterWriter.Write(DateTimeUtils.DateTimeToEpochMilliseconds(encryptParams.TokenExpiry));
            masterWriter.Write((int)siteKey.Id);
            masterWriter.Write(encryptedIdentity);

            byte[] masterIv = new byte[16];
            ThreadSafeRandom.PerThread.NextBytes(masterIv);
            byte[] encryptedMasterPayload = Encrypt(masterStream.ToArray(), masterIv, masterKey.Secret);

            var rootStream = new MemoryStream();
            var rootWriter = new BigEndianByteWriter(rootStream);
            rootWriter.Write((byte)2);
            rootWriter.Write((int)masterKey.Id);
            rootWriter.Write(encryptedMasterPayload);

            return Convert.ToBase64String(rootStream.ToArray());
        }

        private static byte[] Encrypt(byte[] data, byte[] iv, byte[] secret)
        {
            using (var r = new RijndaelManaged() { Key = secret, IV = iv, Mode = CipherMode.CBC })
            using (var m = new MemoryStream(data))
            using (var cs = new CryptoStream(m, r.CreateEncryptor(), CryptoStreamMode.Read))
            using (var ms = new MemoryStream())
            {
                ms.Write(iv, 0, 16);
                cs.CopyTo(ms);

                return ms.ToArray();
            }
        }
    }
}
