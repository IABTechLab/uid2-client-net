using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using UID2.Client.Utils;

namespace UID2.Client
{
    internal enum ClientType
    {
        Sharing,
        Bidstream,
        LegacyWithoutDomainOrAppNameCheck,
        LegacyWithDomainOrAppNameCheck
    }

    public class TokenDetails
    {
        public TokenDetails(DecryptionStatus status = DecryptionStatus.Success)
        {
            this.decryptionStatus = status;
        }

        //todo, capitalize and get/set
        public IdentityScope? identityScope;
        public IdentityType? identityType;
        public byte tokenVersion;
        public int masterKeyId;
        
        public byte[] masterIv;
        //masterPayload
        //masterGMAC (v3,4 only)

        //Maater payload
        public DateTime expiry;
        public DateTime? generated;
        public int? operatorSiteId;
        public byte? operatorType;
        public int? operatorVersion;
        public int? operatorKeyId;

        public int siteKeyId; //"Site Key ID of the key for the identity payload"
        //identityIv
        //identityPayload
        //identityGMAC

        //IdentityPayload
        public int siteId;
        public long? publisherId;
        public int? publisherKeyId; //"Client Key Id"

        public PrivacyBits privacyBits;
        public DateTime established;
        public DateTime? refreshed;

        public int? idLength;
        public string idString;

        public DecryptionStatus decryptionStatus;
    }

    internal static class UID2Encryption
    {
        public const int GCM_AUTHTAG_LENGTH = 16;
        public const int GCM_IV_LENGTH = 12;
        public const int TOKEN_V2_LENGTH = 133;
        public const int TOKEN_V3_MIN_LENGTH = 163;
        private static char[] BASE64_URL_SPECIAL_CHARS = { '-', '_' };


        internal static TokenDetails DecryptTokenDetails(string token, KeyContainer keys, DateTime now, string domainOrAppName, IdentityScope identityScope, ClientType clientType)
        {
            if (token.Length < 4)
            {
                return new TokenDetails(DecryptionStatus.InvalidPayload);
            }

            string headerStr = token.Substring(0, 4);
            Boolean isBase64UrlEncoding = headerStr.IndexOfAny(BASE64_URL_SPECIAL_CHARS) != -1;
            byte[] data = isBase64UrlEncoding ? UID2Base64UrlCoder.Decode(headerStr) : Convert.FromBase64String(headerStr);

            if (data[0] == 2)
            {
                return DecryptV2(Convert.FromBase64String(token), keys, now, domainOrAppName, clientType);
            }
            
            if (data[1] == (int)AdvertisingTokenVersion.V3)
            {
                return DecryptV3(Convert.FromBase64String(token), keys, now, identityScope, 3, domainOrAppName, clientType);
            }

            if (data[1] == (int)AdvertisingTokenVersion.V4)
            {
                //same as V3 but use Base64URL encoding
                return DecryptV3(UID2Base64UrlCoder.Decode(token), keys, now, identityScope, 4, domainOrAppName, clientType);
            }

            return new TokenDetails(DecryptionStatus.VersionNotSupported);
        }

        private static TokenDetails DecryptV2(byte[] encryptedId, KeyContainer keys, DateTime now, string domainOrAppName, ClientType clientType)
        {
            var tokenDetails = new TokenDetails();
            if (encryptedId.Length != TOKEN_V2_LENGTH)
            {
                tokenDetails.decryptionStatus = DecryptionStatus.InvalidPayload;
                return tokenDetails;
            }
            
            var reader = new BigEndianByteReader(new MemoryStream(encryptedId));


            tokenDetails.tokenVersion = reader.ReadByte();

            tokenDetails.masterKeyId = reader.ReadInt32();

            Key masterKey = null;
            if (!keys.TryGetKey(tokenDetails.masterKeyId, out masterKey))
            {
                tokenDetails.decryptionStatus = DecryptionStatus.NotAuthorizedForMasterKey;
                return tokenDetails;
            }

            tokenDetails.masterIv = reader.ReadBytes(16);

            var masterDecrypted = Decrypt(new ByteArraySlice(encryptedId, 21, encryptedId.Length - 21), tokenDetails.masterIv, masterKey.Secret);

            var masterPayloadReader = new BigEndianByteReader(new MemoryStream(masterDecrypted));

            var expiresMilliseconds = masterPayloadReader.ReadInt64();

            tokenDetails.siteKeyId = masterPayloadReader.ReadInt32();

            Key siteKey = null;
            if (!keys.TryGetKey(tokenDetails.siteKeyId, out siteKey))
            {
                tokenDetails.decryptionStatus = DecryptionStatus.NotAuthorizedForKey;
                return tokenDetails;
            }

            //var identityDecrypted = Decrypt(new ByteArraySlice(masterDecrypted, 28, masterDecrypted.Length - 28), masterPayloadReader.ReadBytes(16), siteKey.Secret);
            var identityDecrypted = Decrypt(new ByteArraySlice(masterDecrypted, 28, masterDecrypted.Length - 28), masterPayloadReader.ReadBytes(16), siteKey.Secret);

            var identityPayloadReader = new BigEndianByteReader(new MemoryStream(identityDecrypted));

            tokenDetails.siteId = identityPayloadReader.ReadInt32();
            tokenDetails.idLength = identityPayloadReader.ReadInt32();

            tokenDetails.idString = Encoding.UTF8.GetString(identityPayloadReader.ReadBytes((int)tokenDetails.idLength));

            tokenDetails.privacyBits = new PrivacyBits(identityPayloadReader.ReadInt32());

            var establishedMilliseconds = identityPayloadReader.ReadInt64();

            tokenDetails.established = DateTimeUtils.FromEpochMilliseconds(establishedMilliseconds);

            tokenDetails.expiry = DateTimeUtils.FromEpochMilliseconds(expiresMilliseconds);
            if (tokenDetails.expiry < now)
            {
                tokenDetails.decryptionStatus = DecryptionStatus.ExpiredToken;
            }

            if (tokenDetails.privacyBits.IsOptedOut)
            {
                tokenDetails.decryptionStatus = DecryptionStatus.UserOptedOut;
            }

            if (!IsDomainOrAppNameAllowedForSite(clientType, tokenDetails.privacyBits, tokenDetails.siteId, domainOrAppName, keys))
            {
                tokenDetails.decryptionStatus = DecryptionStatus.DomainOrAppNameCheckFailed;
            }

            if (!DoesTokenHaveValidLifetime(clientType, keys, now, tokenDetails.expiry, now))
            {
                tokenDetails.decryptionStatus = DecryptionStatus.InvalidTokenLifetime;
            }

            tokenDetails.decryptionStatus = DecryptionStatus.Success;
            return tokenDetails;
        }

        private static TokenDetails DecryptV3(byte[] encryptedId, KeyContainer keys, DateTime now, IdentityScope identityScope, int advertisingTokenVersion, string domainOrAppName, ClientType clientType)
        {
            var tokenDetails = new TokenDetails();
            if (encryptedId.Length < TOKEN_V3_MIN_LENGTH)
            {
                tokenDetails.decryptionStatus = DecryptionStatus.InvalidPayload;
                return tokenDetails;
            }

            tokenDetails.identityType = GetIdentityType(encryptedId);
            
            var reader = new BigEndianByteReader(new MemoryStream(encryptedId));

            var prefix = reader.ReadByte();
            tokenDetails.identityScope = DecodeIdentityScopeV3(prefix);
            if (tokenDetails.identityScope != identityScope) 
            {
                tokenDetails.decryptionStatus = DecryptionStatus.InvalidIdentityScope;
                return tokenDetails;
            }

            tokenDetails.tokenVersion = reader.ReadByte();

            tokenDetails.masterKeyId = reader.ReadInt32();

            if (!keys.TryGetKey(tokenDetails.masterKeyId, out var masterKey))
            {
                tokenDetails.decryptionStatus = DecryptionStatus.NotAuthorizedForMasterKey;
                return tokenDetails;
            }

            var masterDecrypted = DecryptGCM(new ByteArraySlice(encryptedId, 6, encryptedId.Length - 6), masterKey.Secret);
            var masterPayloadReader = new BigEndianByteReader(new MemoryStream(masterDecrypted));

            long expiresMilliseconds = masterPayloadReader.ReadInt64();
            long generatedMilliseconds = masterPayloadReader.ReadInt64();
            tokenDetails.generated = DateTimeUtils.FromEpochMilliseconds(generatedMilliseconds);

            tokenDetails.operatorSiteId = masterPayloadReader.ReadInt32();
            tokenDetails.operatorType = masterPayloadReader.ReadByte();
            tokenDetails.operatorVersion = masterPayloadReader.ReadInt32();
            tokenDetails.operatorKeyId = masterPayloadReader.ReadInt32();

            tokenDetails.siteKeyId = masterPayloadReader.ReadInt32();

            if (!keys.TryGetKey(tokenDetails.siteKeyId, out var siteKey))
            {
                tokenDetails.decryptionStatus = DecryptionStatus.NotAuthorizedForKey;
                return tokenDetails;
            }

            var sitePayload = DecryptGCM(new ByteArraySlice(masterDecrypted, 33, masterDecrypted.Length - 33), siteKey.Secret);
            var sitePayloadReader = new BigEndianByteReader(new MemoryStream(sitePayload));

            tokenDetails.siteId = sitePayloadReader.ReadInt32();
            tokenDetails.publisherId = sitePayloadReader.ReadInt64();
            tokenDetails.publisherKeyId = sitePayloadReader.ReadInt32();

            tokenDetails.privacyBits = new PrivacyBits(sitePayloadReader.ReadInt32());

            var establishedMilliseconds = sitePayloadReader.ReadInt64();
            tokenDetails.established = DateTimeUtils.FromEpochMilliseconds(establishedMilliseconds);
            var refreshedMilliseconds = sitePayloadReader.ReadInt64();
            tokenDetails.refreshed = DateTimeUtils.FromEpochMilliseconds(refreshedMilliseconds);

            var id = sitePayloadReader.ReadBytes(sitePayload.Length - 36);

            tokenDetails.idString = Convert.ToBase64String(id);

            tokenDetails.expiry = DateTimeUtils.FromEpochMilliseconds(expiresMilliseconds);
            if (tokenDetails.expiry < now)
            {
                tokenDetails.decryptionStatus = DecryptionStatus.ExpiredToken;
            }

            if (tokenDetails.privacyBits.IsOptedOut)
            {
                tokenDetails.decryptionStatus = DecryptionStatus.UserOptedOut;
            }

            if (!IsDomainOrAppNameAllowedForSite(clientType, tokenDetails.privacyBits, tokenDetails.siteId, domainOrAppName, keys))
            {
                tokenDetails.decryptionStatus = DecryptionStatus.DomainOrAppNameCheckFailed;
            }

            if (!DoesTokenHaveValidLifetime(clientType, keys, (DateTime)tokenDetails.generated, tokenDetails.expiry, now))
                tokenDetails.decryptionStatus = DecryptionStatus.InvalidTokenLifetime;

            return tokenDetails;
        }

        private static bool DoesTokenHaveValidLifetime(ClientType clientType, KeyContainer keys, DateTime generatedOrNow, DateTime expiry, DateTime now)
        {
            long maxLifetimeSeconds;
            switch (clientType)
            {
                case ClientType.Bidstream:
                    maxLifetimeSeconds = keys.MaxBidstreamLifetimeSeconds;
                    break;
                case ClientType.Sharing:
                    maxLifetimeSeconds = keys.MaxSharingLifetimeSeconds;
                    break;
                default: //Legacy
                    return true;
            }

            //generatedOrNow allows "now" for token v2, since v2 does not contain a "token generated" field. v2 therefore checks against remaining lifetime rather than total lifetime.
            return DoesTokenHaveValidLifetimeImpl(generatedOrNow, expiry, now, maxLifetimeSeconds, keys.AllowClockSkewSeconds);
        }


        private static bool DoesTokenHaveValidLifetimeImpl(DateTime generatedOrNow, DateTime expiry, DateTime now, long maxLifetimeSeconds, long allowClockSkewSeconds)
        {
            if ((expiry - generatedOrNow).TotalSeconds > maxLifetimeSeconds)
                return false;

            return (generatedOrNow - now).TotalSeconds <= allowClockSkewSeconds; //returns false if token generated too far in the future
        }

        private static bool IsDomainOrAppNameAllowedForSite(ClientType clientType, PrivacyBits privacyBits, int siteId, string domainOrAppName, KeyContainer keys)
        {
            if (!privacyBits.IsClientSideGenerated)
                return true;

            if (clientType != ClientType.Bidstream && clientType != ClientType.LegacyWithDomainOrAppNameCheck)
                return true;

            return keys.IsDomainOrAppNameAllowedForSite(siteId, domainOrAppName);
        }

        internal static EncryptionDataResponse Encrypt(string rawUid, KeyContainer keys, IdentityScope identityScope, DateTime now)
        {
            if (keys == null)
            {
                return EncryptionDataResponse.MakeError(EncryptionStatus.NotInitialized);
            }
            else if (!keys.IsValid(now))
            {
                return EncryptionDataResponse.MakeError(EncryptionStatus.KeysNotSynced);
            }


            if (!keys.TryGetMasterKey(now, out var masterKey))
            {
                return EncryptionDataResponse.MakeError(EncryptionStatus.NotAuthorizedForMasterKey);
            }

            if (!keys.TryGetDefaultKey(now, out var defaultKey))
            {
                return EncryptionDataResponse.MakeError(EncryptionStatus.NotAuthorizedForKey);
            }

            var expiry = now.AddSeconds(keys.TokenExpirySeconds);
#pragma warning disable CS0618 //warning CS0618: 'UID2TokenGenerator' is obsolete: 'This class shouldn't be used outside of the SDK and will be made internal in a future release'
            var encryptParams = UID2TokenGenerator.DefaultParams.WithTokenGenerated(now).WithTokenExpiry(expiry);

            try
            {
                string advertisingToken = (identityScope == IdentityScope.UID2)
                    ? UID2TokenGenerator.GenerateUid2TokenV4(rawUid, masterKey, keys.CallerSiteId, defaultKey, encryptParams)
                    : UID2TokenGenerator.GenerateEuidTokenV4(rawUid, masterKey, keys.CallerSiteId, defaultKey, encryptParams);
#pragma warning restore CS0618 //warning CS0618: 'UID2TokenGenerator' is obsolete: 'This class shouldn't be used outside of the SDK and will be made internal in a future release'
                return EncryptionDataResponse.MakeSuccess(advertisingToken);
            }
            catch (Exception)
            {
                return EncryptionDataResponse.MakeError(EncryptionStatus.EncryptionFailure);
            }
        }

        internal static EncryptionDataResponse EncryptData(EncryptionDataRequest request, KeyContainer keys, IdentityScope identityScope)
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
                int siteKeySiteId = -1;
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
                    siteKeySiteId = siteId;
                }
                else
                {
                    try
                    {
                        // if the enableDomainOrAppNameCheck param is enabled , the caller would have to provide siteId as part of the EncryptionDataRequest.
                        var tokenDetails = DecryptTokenDetails(request.AdvertisingToken, keys, now, domainOrAppName: null, identityScope, ClientType.LegacyWithoutDomainOrAppNameCheck);
                        if (tokenDetails.decryptionStatus != DecryptionStatus.Success)
                        {
                            return EncryptionDataResponse.MakeError(EncryptionStatus.TokenDecryptFailure);
                        }

                        siteId = tokenDetails.siteId;
                        siteKeySiteId = tokenDetails.siteKeyId;
                    }
                    catch (Exception)
                    {
                        return EncryptionDataResponse.MakeError(EncryptionStatus.TokenDecryptFailure);
                    }
                }

                if (!keys.TryGetActiveSiteKey(siteKeySiteId, now, out key))
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
                iv = GenerateIV(GCM_IV_LENGTH);
            }

            try
            {
                var payloadStream = new MemoryStream(request.Data.Length + 12);
                var payloadWriter = new BigEndianByteWriter(payloadStream);
                payloadWriter.Write(DateTimeUtils.DateTimeToEpochMilliseconds(now));
                payloadWriter.Write(siteId);
                payloadWriter.Write(request.Data);

                byte[] encryptedData = EncryptGCM(payloadStream.ToArray(), iv, key.Secret);
                var ms = new MemoryStream(encryptedData.Length + GCM_IV_LENGTH + GCM_AUTHTAG_LENGTH + 6);
                var writer = new BigEndianByteWriter(ms);
                writer.Write((byte)((int)PayloadType.ENCRYPTED_DATA_V3 | ((int)identityScope << 4) | 0xB));
                writer.Write((byte)112); // version
                writer.Write((int)key.Id);
                writer.Write(iv);
                writer.Write(encryptedData);
                return EncryptionDataResponse.MakeSuccess(Convert.ToBase64String(ms.ToArray()));
            }
            catch (Exception)
            {
                return EncryptionDataResponse.MakeError(EncryptionStatus.EncryptionFailure);
            }
        }

        internal static DecryptionDataResponse DecryptData(byte[] encryptedBytes, KeyContainer keys, IdentityScope identityScope)
        {
            if ((encryptedBytes[0] & 224) == (int)PayloadType.ENCRYPTED_DATA_V3)
            {
                return DecryptDataV3(encryptedBytes, keys, identityScope);
            }
            else
            {
                return DecryptDataV2(encryptedBytes, keys);
            }
        }

        internal static DecryptionDataResponse DecryptDataV2(byte[] encryptedBytes, KeyContainer keys)
        {
            var reader = new BigEndianByteReader(new MemoryStream(encryptedBytes));
            if (reader.ReadByte() != (byte)PayloadType.ENCRYPTED_DATA)
            {
                return DecryptionDataResponse.MakeError(DecryptionStatus.InvalidPayloadType);
            }

            if (reader.ReadByte() != 1)
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

        internal static DecryptionDataResponse DecryptDataV3(byte[] encryptedBytes, KeyContainer keys, IdentityScope identityScope)
        {
            var reader = new BigEndianByteReader(new MemoryStream(encryptedBytes));
            var payloadScope = DecodeIdentityScopeV3(reader.ReadByte());
            if (payloadScope != identityScope)
            {
                return DecryptionDataResponse.MakeError(DecryptionStatus.InvalidIdentityScope);
            }

            if (reader.ReadByte() != 112)
            {
                return DecryptionDataResponse.MakeError(DecryptionStatus.VersionNotSupported);
            }

            long keyId = reader.ReadInt32();
            if (!keys.TryGetKey(keyId, out var key))
            {
                return DecryptionDataResponse.MakeError(DecryptionStatus.NotAuthorizedForKey);
            }

            var decryptedBytes = DecryptGCM(new ByteArraySlice(encryptedBytes, 6, encryptedBytes.Length - 6), key.Secret);
            var decryptedReader = new BigEndianByteReader(new MemoryStream(decryptedBytes));

            DateTime encryptedAt = DateTimeUtils.FromEpochMilliseconds(decryptedReader.ReadInt64());
            int siteId = decryptedReader.ReadInt32();

            var decryptedData = new byte[decryptedBytes.Length - 12];
            Array.Copy(decryptedBytes, 12, decryptedData, 0, decryptedData.Length);

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

        internal static (byte[], byte[]) EncryptGCM(byte[] data, byte[] secret)
        {
            var iv = GenerateIV(GCM_IV_LENGTH);
            return (iv, EncryptGCM(data, iv, secret));
        }

        internal static byte[] EncryptGCM(byte[] data, byte[] iv, byte[] secret)
        {
            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(secret), GCM_AUTHTAG_LENGTH * 8, iv, null);
            cipher.Init(true, parameters);
            var cipherText = new byte[cipher.GetOutputSize(data.Length)];
            var len = cipher.ProcessBytes(data, 0, data.Length, cipherText, 0);
            cipher.DoFinal(cipherText, len);
            return cipherText;
        }

        internal static byte[] DecryptGCM(ByteArraySlice cipherText, byte[] secret)
        {
            var iv = new byte[GCM_IV_LENGTH];
            Array.Copy(cipherText.Buffer, cipherText.Offset, iv, 0, iv.Length);
            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(secret), GCM_AUTHTAG_LENGTH * 8, iv, null);
            cipher.Init(false, parameters);
            var plainText = new byte[cipher.GetOutputSize(cipherText.Count - GCM_IV_LENGTH)];
            var len = cipher.ProcessBytes(cipherText.Buffer, cipherText.Offset + GCM_IV_LENGTH, cipherText.Count - GCM_IV_LENGTH, plainText, 0);
            cipher.DoFinal(plainText, len);
            return plainText;
        }

        private static byte[] GenerateIV(int len = 16)
        {
            byte[] iv = new byte[len];
            RNGCryptoServiceProvider.Create().GetBytes(iv);
            return iv;
        }

        private static IdentityScope DecodeIdentityScopeV3(byte value)
        {
            return (IdentityScope)((value >> 4) & 1);
        }

        private static IdentityType GetIdentityType(byte[] encryptedId)
        {
            // For specifics about the bitwise logic, check:
            // Confluence - UID2-79 UID2 Token v3/v4 and Raw UID2 format v3
            // In the base64-encoded version of encryptedId, the first character is always either A/B/E/F.
            // After converting to binary and performing the AND operation against 1100,the result is always 0X00.
            // So just bitshift right twice to get 000X, which results in either 0 or 1.
            byte idType = encryptedId[0];
            byte piiType = (byte)((idType & 0b_1100) >> 2);
            return piiType == 0 ? IdentityType.Email : IdentityType.Phone;
        }
    }
}