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

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
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

            public int IdentityScope = (int)UID2.Client.IdentityScope.UID2;
            public int IdentityType = (int)UID2.Client.IdentityType.Email;
        }

        public static Params DefaultParams => new Params();

        public static string GenerateUID2TokenV2(string uid, Key masterKey, int siteId, Key siteKey)
        {
            return GenerateUID2TokenV2(uid, masterKey, siteId, siteKey, DefaultParams);
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
        public static string GenerateUID2TokenV2(string uid, Key masterKey, int siteId, Key siteKey, Params encryptParams)
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

        public static string GenerateUID2TokenV3(string uid, Key masterKey, int siteId, Key siteKey)
        {
            return GenerateUID2TokenV3(uid, masterKey, siteId, siteKey, DefaultParams);
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
        public static string GenerateUID2TokenV3(string uid, Key masterKey, int siteId, Key siteKey, Params encryptParams)
        {
            var sitePayload = new MemoryStream();
            var sitePayloadWriter = new BigEndianByteWriter(sitePayload);

            // publisher data
            sitePayloadWriter.Write(siteId);
            sitePayloadWriter.Write(0L); // publisher id
            sitePayloadWriter.Write(0); // client key id

            // user identity data
            sitePayloadWriter.Write(0); // privacy bits
            sitePayloadWriter.Write(DateTimeUtils.DateTimeToEpochMilliseconds(DateTime.UtcNow.AddHours(-1))); // established
            sitePayloadWriter.Write(DateTimeUtils.DateTimeToEpochMilliseconds(DateTime.UtcNow)); // last refreshed
            sitePayloadWriter.Write(Convert.FromBase64String(uid));

            var masterPayload = new MemoryStream();
            var masterPayloadWriter = new BigEndianByteWriter(masterPayload);
            masterPayloadWriter.Write(DateTimeUtils.DateTimeToEpochMilliseconds(encryptParams.TokenExpiry));
            masterPayloadWriter.Write(DateTimeUtils.DateTimeToEpochMilliseconds(DateTime.UtcNow)); // token created

            // operator identity data
            masterPayloadWriter.Write(0); // site id
            masterPayloadWriter.Write((byte)1); // operator type
            masterPayloadWriter.Write(0); // operator version
            masterPayloadWriter.Write(0); // operator key id
            masterPayloadWriter.Write((int)siteKey.Id);

            byte[] siteIv = new byte[12];
            ThreadSafeRandom.PerThread.NextBytes(siteIv);
            masterPayloadWriter.Write(siteIv);
            masterPayloadWriter.Write(EncryptGCM(sitePayload.ToArray(), siteIv, siteKey.Secret));

            var rootStream = new MemoryStream();
            var rootStreamWriter = new BigEndianByteWriter(rootStream);
            rootStreamWriter.Write((byte)((encryptParams.IdentityScope << 4) | (encryptParams.IdentityType << 2)));
            rootStreamWriter.Write((byte)112);
            rootStreamWriter.Write((int)masterKey.Id);

            byte[] masterIv = new byte[12];
            ThreadSafeRandom.PerThread.NextBytes(masterIv);
            rootStreamWriter.Write(masterIv);
            rootStreamWriter.Write(EncryptGCM(masterPayload.ToArray(), masterIv, masterKey.Secret));

            return Convert.ToBase64String(rootStream.ToArray());
        }

        public static string EncryptDataV2(byte[] data, Key key, int siteId, DateTime now)
        {
            var iv = new byte[16];
            ThreadSafeRandom.PerThread.NextBytes(iv);
            byte[] encryptedData = Encrypt(data, iv, key.Secret);
            
            var ms = new MemoryStream(encryptedData.Length);
            var writer = new BigEndianByteWriter(ms);
            writer.Write((byte)PayloadType.ENCRYPTED_DATA);
            writer.Write((byte)1); // version
            writer.Write(DateTimeUtils.DateTimeToEpochMilliseconds(now));
            writer.Write(siteId);
            writer.Write((int)key.Id);
            writer.Write(encryptedData);

            return Convert.ToBase64String(ms.ToArray());
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

        private static byte[] EncryptGCM(byte[] data, byte[] iv, byte[] secret)
        {
            const int GCM_TAG_LEN = 16;
            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(secret), GCM_TAG_LEN * 8, iv, null);
            cipher.Init(true, parameters);
            var cipherText = new byte[cipher.GetOutputSize(data.Length)];
            var len = cipher.ProcessBytes(data, 0, data.Length, cipherText, 0);
            cipher.DoFinal(cipherText, len);
            return cipherText;
        }
    }
}
