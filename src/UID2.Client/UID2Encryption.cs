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

namespace UID2.Client
{
    internal static class UID2Encryption
    {
        internal static DecryptionResponse Decrypt(byte[] encryptedId, IKeyContainer keys, DateTime now)
        {
            var reader = new BigEndianByteReader(new MemoryStream(encryptedId));

            var version = (int)reader.ReadByte();
            if (version != 2)
            {
                return DecryptionResponse.MakeError(DecryptionStatus.VersionNotSupported);
            }

            var masterKeyId = reader.ReadInt32();

            Key masterKey = null;
            if (!keys.TryGetKey(masterKeyId, out masterKey))
            {
                return DecryptionResponse.MakeError(DecryptionStatus.NotAuthorizedForKey);
            }

            var masterDecrypted = Decrypt(new ByteArraySlice(encryptedId, 21, encryptedId.Length - 21), reader.ReadBytes(16), masterKey.Secret);

            var masterPayloadReader = new BigEndianByteReader(new MemoryStream(masterDecrypted));

            long expiresMilliseconds = masterPayloadReader.ReadInt64();
            var siteKeyId = masterPayloadReader.ReadInt32();

            Key siteKey = null;
            if (!keys.TryGetKey(siteKeyId, out siteKey))
            {
                return DecryptionResponse.MakeError(DecryptionStatus.NotAuthorizedForKey);
            }

            var identityDecrypted =
                Decrypt(new ByteArraySlice(masterDecrypted, 28, masterDecrypted.Length - 28),
                    masterPayloadReader.ReadBytes(16), siteKey.Secret);

            var identityPayloadReader = new BigEndianByteReader(new MemoryStream(identityDecrypted));

            var siteId = identityPayloadReader.ReadInt32();

            var expiry = DateTimeUtils.FromEpochMilliseconds(expiresMilliseconds);
            if (expiry < now)
            {
                return DecryptionResponse.MakeError(DecryptionStatus.ExpiredToken, siteId);
            }

            var idLength = identityPayloadReader.ReadInt32();

            var idString = Encoding.UTF8.GetString(identityPayloadReader.ReadBytes(idLength));

            var privacyBits = identityPayloadReader.ReadInt32();

            var establishedMilliseconds = identityPayloadReader.ReadInt64();

            var established = DateTimeUtils.FromEpochMilliseconds(establishedMilliseconds);

            return DecryptionResponse.MakeSuccess(idString, established, siteId);
        }

        internal static EncryptionDataResponse EncryptData(EncryptionDataRequest request, IKeyContainer keys)
        {
            if (request.Data == null)
            {
                throw new ArgumentNullException("data");
            }

            DateTime now = request.Now;
            Key key = request.Key;
            int siteId = -1;
            if (key == null)
            {
                if (keys == null)
                {
                    return EncryptionDataResponse.MakeError(EncryptionStatus.NotInitialized);
                }
                else if (!keys.IsValid(now))
                {
                    return EncryptionDataResponse.MakeError(EncryptionStatus.KeysNotSynced);
                }
                else if (request.SiteId.HasValue && request.AdvertisingToken != null)
                {
                    throw new ArgumentException("only one of siteId or advertisingToken can be specified");
                }
                else if (request.SiteId.HasValue)
                {
                    siteId = request.SiteId.Value;
                }
                else
                {
                    try
                    {
                        DecryptionResponse decryptedToken = Decrypt(Convert.FromBase64String(request.AdvertisingToken), keys, now);
                        if (!decryptedToken.Success)
                        {
                            return EncryptionDataResponse.MakeError(EncryptionStatus.TokenDecryptFailure);
                        }

                        siteId = decryptedToken.SiteId.Value;
                    }
                    catch (Exception)
                    {
                        return EncryptionDataResponse.MakeError(EncryptionStatus.TokenDecryptFailure);
                    }
                }

                if (!keys.TryGetActiveSiteKey(siteId, now, out key))
                {
                    return EncryptionDataResponse.MakeError(EncryptionStatus.NotAuthorizedForKey);
                }
            }
            else if (!key.IsActive(now))
            {
                return EncryptionDataResponse.MakeError(EncryptionStatus.KeyInactive);
            }
            else
            {
                siteId = key.SiteId;
            }

            byte[] iv = request.InitializationVector;
            if (iv == null)
            {
                iv = GenerateIv();
            }

            try
            {
                byte[] encryptedData = Encrypt(request.Data, iv, key.Secret);
                var ms = new MemoryStream(encryptedData.Length + 18);
                var writer = new BigEndianByteWriter(ms);
                writer.Write((byte)PayloadType.ENCRYPTED_DATA);
                writer.Write((byte)1); // version
                writer.Write(DateTimeUtils.DateTimeToEpochMilliseconds(now));
                writer.Write(siteId);
                writer.Write((int)key.Id);
                writer.Write(encryptedData);
                return EncryptionDataResponse.MakeSuccess(Convert.ToBase64String(ms.ToArray()));
            }
            catch (Exception)
            {
                return EncryptionDataResponse.MakeError(EncryptionStatus.EncryptionFailure);
            }
        }

        internal static DecryptionDataResponse DecryptData(byte[] encryptedBytes, IKeyContainer keys)
        {
            var reader = new BigEndianByteReader(new MemoryStream(encryptedBytes));
            if (reader.ReadByte() != (byte)PayloadType.ENCRYPTED_DATA)
            {
                return DecryptionDataResponse.MakeError(DecryptionStatus.InvalidPayloadType);
            }
            else if (reader.ReadByte() != 1)
            {
                return DecryptionDataResponse.MakeError(DecryptionStatus.VersionNotSupported);
            }

            DateTime encryptedAt = DateTimeUtils.FromEpochMilliseconds(reader.ReadInt64());
            int siteId = reader.ReadInt32();
            long keyId = reader.ReadInt32();

            if (!keys.TryGetKey(keyId, out var key))
            {
                return DecryptionDataResponse.MakeError(DecryptionStatus.NotAuthorizedForKey);
            }

            byte[] iv = reader.ReadBytes(16);
            byte[] decryptedData = Decrypt(new ByteArraySlice(encryptedBytes, 34, encryptedBytes.Length - 34), iv, key.Secret);

            return DecryptionDataResponse.MakeSuccess(decryptedData, encryptedAt);
        }

        private static byte[] Decrypt(ByteArraySlice arraySlice, byte[] iv, byte[] secret)
        {
            using (var r = new RijndaelManaged() { Key = secret, IV = iv, Mode = CipherMode.CBC })
            using (var m = new MemoryStream(arraySlice.Buffer, arraySlice.Offset, arraySlice.Count))
            using (var cs = new CryptoStream(m, r.CreateDecryptor(), CryptoStreamMode.Read))
            using (var ms = new MemoryStream())
            {
                cs.CopyTo(ms);
                return ms.ToArray();
            }
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

        private static byte[] GenerateIv()
        {
            byte[] iv = new byte[16];
            RNGCryptoServiceProvider.Create().GetBytes(iv);
            return iv;
        }
    }
}