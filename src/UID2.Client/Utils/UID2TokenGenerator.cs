﻿using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace UID2.Client.Utils
{
    [Obsolete("This class shouldn't be used outside of the SDK and will be made internal in a future release")]
    public static class UID2TokenGenerator
    {
        public class Params
        {
            public DateTime TokenExpiry = DateTime.UtcNow.AddHours(1);
            public int PrivacyBits = 0;
            public DateTime TokenGenerated = DateTime.UtcNow;
            public DateTime IdentityEstablished = DateTime.UtcNow;

            public Params() { }
            public Params WithTokenExpiry(DateTime expiry) { TokenExpiry = expiry; return this; }
            public Params WithPrivacyBits(int privacyBits) { PrivacyBits = privacyBits; return this; }
            public Params WithTokenGenerated(DateTime generated) { TokenGenerated = generated; return this; } //when was the most recent refresh done (or if not refreshed, when was the /token/generate or CSTG call)
            public Params WithIdentityEstablished(DateTime established) { IdentityEstablished = established; return this; } //when was the first call to /token/generate or CSTG

            public int IdentityScope = (int)UID2.Client.IdentityScope.UID2;
        }

        public static Params DefaultParams => new Params();

        public static string GenerateUid2TokenV2(string uid, Key masterKey, int siteId, Key siteKey)
        {
            return GenerateUid2TokenV2(uid, masterKey, siteId, siteKey, DefaultParams);
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
        public static string GenerateUid2TokenV2(string uid, Key masterKey, int siteId, Key siteKey, Params encryptParams)
        {
            var uidBytes = Encoding.UTF8.GetBytes(uid);
            var identityStream = new MemoryStream();
            var identityWriter = new BigEndianByteWriter(identityStream);
            identityWriter.Write(siteId);
            identityWriter.Write(uidBytes.Length);
            identityWriter.Write(uidBytes);
            identityWriter.Write(encryptParams.PrivacyBits);
            identityWriter.Write(DateTimeUtils.DateTimeToEpochMilliseconds(encryptParams.IdentityEstablished));
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

        public static string GenerateUid2TokenV3(string uid, Key masterKey, int siteId, Key siteKey, Params encryptParams)
        {
            return GenerateTokenV3orV4(uid, masterKey, siteId, siteKey, encryptParams, AdvertisingTokenVersion.V3);
        }

        public static string GenerateUid2TokenV4(string uid, Key masterKey, int siteId, Key siteKey, Params encryptParams)
        {
            return GenerateTokenV3orV4(uid, masterKey, siteId, siteKey, encryptParams, AdvertisingTokenVersion.V4);
        }

        public static string GenerateEuidTokenV3(string uid, Key masterKey, int siteId, Key siteKey)
        {
            var param = new Params()
            {
                IdentityScope = (int) IdentityScope.EUID
            };
            return GenerateTokenV3orV4(uid, masterKey, siteId, siteKey, param, AdvertisingTokenVersion.V3);
        }
        
        public static string GenerateEuidTokenV4(string uid, Key masterKey, int siteId, Key siteKey, Params encryptParams)
        {
            encryptParams.IdentityScope = (int)IdentityScope.EUID;

            return GenerateTokenV3orV4(uid, masterKey, siteId, siteKey, encryptParams, AdvertisingTokenVersion.V4);
        }

        /// <summary>
        ///  The data can be decrypted with UID2.Client.IUID2Client.Decrypt method
        /// </summary>
        /// <param name="uid">UID to be encrypted to a UID2 Token</param>
        /// <param name="masterKey">The mandatory key that is not site-specific and would encrypt UID into a UID2 Token</param>
        /// <param name="siteId">The unique identifier of the publisher</param>
        /// <param name="siteKey">site-specific key to encrypt the UID with first before encrypting again with master key</param>
        /// <param name="encryptParams"></param>
        /// <param name="adTokenVersion"></param>
        /// <returns>the encrypted UID in the form of UID2 Token</returns>
        private static string GenerateTokenV3orV4(string uid, Key masterKey, int siteId, Key siteKey, Params encryptParams, AdvertisingTokenVersion adTokenVersion)
        {
            var sitePayload = new MemoryStream();
            var sitePayloadWriter = new BigEndianByteWriter(sitePayload);

            // publisher data
            sitePayloadWriter.Write(siteId);
            sitePayloadWriter.Write(0L); // publisher id
            sitePayloadWriter.Write(0); // client key id

            // user identity data
            sitePayloadWriter.Write(encryptParams.PrivacyBits);
            sitePayloadWriter.Write(DateTimeUtils.DateTimeToEpochMilliseconds(encryptParams.IdentityEstablished)); // established
            sitePayloadWriter.Write(DateTimeUtils.DateTimeToEpochMilliseconds(encryptParams.TokenGenerated)); // last refreshed
            sitePayloadWriter.Write(Convert.FromBase64String(uid));

            var masterPayload = new MemoryStream();
            var masterPayloadWriter = new BigEndianByteWriter(masterPayload);
            masterPayloadWriter.Write(DateTimeUtils.DateTimeToEpochMilliseconds(encryptParams.TokenExpiry));
            masterPayloadWriter.Write(DateTimeUtils.DateTimeToEpochMilliseconds(encryptParams.TokenGenerated)); //identity refreshed, seems to be identical to TokenGenerated in Operator

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
            var firstChar = uid.Substring(0, 1);
            var identityType = (firstChar == "F" || firstChar == "B") ? IdentityType.Phone : IdentityType.Email; //see UID2-79+Token+and+ID+format+v3

            rootStreamWriter.Write((byte)((encryptParams.IdentityScope << 4) | ((int)identityType << 2) | 3));
            rootStreamWriter.Write((byte)adTokenVersion);
            rootStreamWriter.Write((int)masterKey.Id);

            byte[] masterIv = new byte[12];
            ThreadSafeRandom.PerThread.NextBytes(masterIv);
            rootStreamWriter.Write(masterIv);
            rootStreamWriter.Write(EncryptGCM(masterPayload.ToArray(), masterIv, masterKey.Secret));

            if (adTokenVersion == AdvertisingTokenVersion.V4)
            {
                return UID2Base64UrlCoder.Encode(rootStream.ToArray());
            }

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
