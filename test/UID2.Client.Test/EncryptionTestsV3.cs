﻿using System;
using System.Linq;
using UID2.Client.Utils;
using Xunit;

namespace UID2.Client.Test
{
    public class EncryptionTestsV3
    {
        const long MASTER_KEY_ID = 164;
        const long SITE_KEY_ID = 165;
        const int SITE_ID = 9000;
        const int SITE_ID2 = 2;
        const string EXAMPLE_EMAIL_UID = "ywsvDNINiZOVSsfkHpLpSJzXzhr6Jx9Z/4Q0+lsEUvM=";
        const string EXAMPLE_PHONE_UID = "BFOsW2SkK0egqbfyiALtpti5G/cG+PcEvjkoHl56rEV8";
        private static readonly byte[] MASTER_SECRET = { 139, 37, 241, 173, 18, 92, 36, 232, 165, 168, 23, 18, 38, 195, 123, 92, 160, 136, 185, 40, 91, 173, 165, 221, 168, 16, 169, 164, 38, 139, 8, 155 };
        private static readonly byte[] SITE_SECRET = { 32, 251, 7, 194, 132, 154, 250, 86, 202, 116, 104, 29, 131, 192, 139, 215, 48, 164, 11, 65, 226, 110, 167, 14, 108, 51, 254, 125, 65, 24, 23, 133 };
        private static readonly DateTime NOW = DateTime.UtcNow;
        private static readonly Key MASTER_KEY = new Key(MASTER_KEY_ID, -1, NOW.AddDays(-1), NOW, NOW.AddDays(1), MASTER_SECRET);
        private static readonly Key SITE_KEY = new Key(SITE_KEY_ID, SITE_ID, NOW.AddDays(-10), NOW.AddDays(-1), NOW.AddDays(1), SITE_SECRET);
        private static readonly string CLIENT_SECRET = "ioG3wKxAokmp+rERx6A4kM/13qhyolUXIu14WN16Spo=";

        [Theory]
        [InlineData(EXAMPLE_EMAIL_UID, nameof(IdentityScope.UID2), IdentityType.Email)]
        [InlineData(EXAMPLE_PHONE_UID, nameof(IdentityScope.UID2), IdentityType.Phone)]
        [InlineData(EXAMPLE_EMAIL_UID, nameof(IdentityScope.EUID), IdentityType.Email)]
        [InlineData(EXAMPLE_PHONE_UID, nameof(IdentityScope.EUID), IdentityType.Phone)]
        public void IdentityScopeAndType_TestCases(String uid, string identityScope, IdentityType? identityType)
        {
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, Enum.Parse<IdentityScope>(identityScope));
            var refreshResult = client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            Assert.True(refreshResult.Success);

            string advertisingToken = identityScope == "UID2"
                ? UID2TokenGenerator.GenerateUid2TokenV3(uid, MASTER_KEY, SITE_ID, SITE_KEY, UID2TokenGenerator.DefaultParams)
                : UID2TokenGenerator.GenerateEuidTokenV3(uid, MASTER_KEY, SITE_ID, SITE_KEY);
            var res = client.Decrypt(advertisingToken, NOW);
            Assert.True(res.Success);
            Assert.Equal(uid, res.Uid);
            Assert.Equal(identityType, res.IdentityType);
            Assert.Equal(3, res.AdvertisingTokenVersion);
        }

        [Fact]
        public void SmokeTest()
        {
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            var refreshResult = client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            Assert.True(refreshResult.Success);
            
            string advertisingToken = UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_EMAIL_UID, MASTER_KEY, SITE_ID, SITE_KEY, UID2TokenGenerator.DefaultParams);
            var res = client.Decrypt(advertisingToken, NOW);
            Assert.True(res.Success);
            Assert.Equal(EXAMPLE_EMAIL_UID, res.Uid);
            Assert.Equal(IdentityType.Email, res.IdentityType);
            Assert.Equal(3, res.AdvertisingTokenVersion);
        }

        [Fact]
        public void EmptyKeyContainer()
        {
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            var advertisingToken = UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_EMAIL_UID, MASTER_KEY, SITE_ID, SITE_KEY, UID2TokenGenerator.DefaultParams);
            var res = client.Decrypt(advertisingToken, NOW);
            Assert.False(res.Success);
            Assert.Equal(DecryptionStatus.NotInitialized, res.Status);
        }

        [Fact]
        public void ExpiredKeyContainer()
        {
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            var advertisingToken = UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_EMAIL_UID, MASTER_KEY, SITE_ID, SITE_KEY, UID2TokenGenerator.DefaultParams);

            Key masterKeyExpired = new Key(MASTER_KEY_ID, -1, NOW, NOW.AddHours(-2), NOW.AddHours(-1), MASTER_SECRET);
            Key siteKeyExpired = new Key(SITE_KEY_ID, SITE_ID, NOW, NOW.AddHours(-2), NOW.AddHours(-1), SITE_SECRET);
            client.RefreshJson(KeySetToJson(masterKeyExpired, siteKeyExpired));

            var res = client.Decrypt(advertisingToken, NOW);
            Assert.False(res.Success);
            Assert.Equal(DecryptionStatus.KeysNotSynced, res.Status);
        }

        [Fact]
        public void NotAuthorizedForKey()
        {
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            var advertisingToken = UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_EMAIL_UID, MASTER_KEY, SITE_ID, SITE_KEY, UID2TokenGenerator.DefaultParams);

            Key anotherMasterKey = new Key(MASTER_KEY_ID + SITE_KEY_ID + 1, -1, NOW, NOW, NOW.AddHours(1), MASTER_SECRET);
            Key anotherSiteKey = new Key(MASTER_KEY_ID + SITE_KEY_ID + 2, SITE_ID, NOW, NOW, NOW.AddHours(1), SITE_SECRET);
            client.RefreshJson(KeySetToJson(anotherMasterKey, anotherSiteKey));

            var res = client.Decrypt(advertisingToken, NOW);
            Assert.Equal(DecryptionStatus.NotAuthorizedForMasterKey, res.Status);
        }

        [Fact]
        public void InvalidPayload()
        {
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            byte[] payload = Convert.FromBase64String(UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_EMAIL_UID, MASTER_KEY, SITE_ID, SITE_KEY, UID2TokenGenerator.DefaultParams));
            var advertisingToken = Convert.ToBase64String(payload.SkipLast(1).ToArray());

            client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));

            var res = client.Decrypt(advertisingToken, NOW);
            Assert.Equal(DecryptionStatus.InvalidPayload, res.Status);
        }

        [Fact]
        public void TokenExpiryAndCustomNow()
        {
            var expiry = NOW.AddDays(-60);
            var encryptParams = UID2TokenGenerator.DefaultParams.WithTokenExpiry(expiry);

            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            var advertisingToken = UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_EMAIL_UID, MASTER_KEY, SITE_ID, SITE_KEY, encryptParams);

            var res = client.Decrypt(advertisingToken, expiry.AddSeconds(1));
            Assert.Equal(DecryptionStatus.ExpiredToken, res.Status);

            res = client.Decrypt(advertisingToken, expiry.AddSeconds(-1));
            Assert.Equal(EXAMPLE_EMAIL_UID, res.Uid);
        }

        [Fact]
        public void EncryptDataSpecificKeyAndIv()
        {
            byte[] data = { 1, 2, 3, 4, 5, 6 };
            byte[] iv = new byte[12];
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            var encrypted = client.EncryptData(EncryptionDataRequest.ForData(data).WithKey(SITE_KEY).WithInitializationVector(iv));
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            client.RefreshJson(KeySetToJson(SITE_KEY));
            var decrypted = client.DecryptData(encrypted.EncryptedData);
            Assert.Equal(DecryptionStatus.Success, decrypted.Status);
            Assert.Equal(data, decrypted.DecryptedData);
        }

        [Fact]
        public void EncryptDataSpecificKeyAndGeneratedIv()
        {
            byte[] data = { 1, 2, 3, 4, 5, 6};
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            var encrypted = client.EncryptData(EncryptionDataRequest.ForData(data).WithKey(SITE_KEY));
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            client.RefreshJson(KeySetToJson(SITE_KEY));
            var decrypted = client.DecryptData(encrypted.EncryptedData);
            Assert.Equal(DecryptionStatus.Success, decrypted.Status);
            Assert.Equal(data, decrypted.DecryptedData);
        }

        [Fact]
        public void EncryptDataSpecificSiteId()
        {
            byte[] data = { 1, 2, 3, 4, 5, 6 };
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            client.RefreshJson(KeySetToJson(SITE_KEY));
            var encrypted = client.EncryptData(EncryptionDataRequest.ForData(data).WithSiteId(SITE_KEY.SiteId));
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            var decrypted = client.DecryptData(encrypted.EncryptedData);
            Assert.Equal(DecryptionStatus.Success, decrypted.Status);
            Assert.Equal(data, decrypted.DecryptedData);
        }

        [Fact]
        public void EncryptDataSiteIdFromToken()
        {
            byte[] data = { 1, 2, 3, 4, 5, 6};
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            string advertisingToken = UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_EMAIL_UID, MASTER_KEY, SITE_ID, SITE_KEY, UID2TokenGenerator.DefaultParams);
            var encrypted = client.EncryptData(EncryptionDataRequest.ForData(data).WithAdvertisingToken(advertisingToken));
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            var decrypted = client.DecryptData(encrypted.EncryptedData);
            Assert.Equal(DecryptionStatus.Success, decrypted.Status);
            Assert.Equal(data, decrypted.DecryptedData);
        }
        
        [Fact]
        public void EncryptDataSiteIdFromTokenCustomSiteKeySiteId()
        {
            byte[] data = {1, 2, 3, 4, 5, 6};
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            string advertisingToken = UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_EMAIL_UID, MASTER_KEY, SITE_ID2, SITE_KEY, UID2TokenGenerator.DefaultParams);
            var encrypted = client.EncryptData(EncryptionDataRequest.ForData(data).WithAdvertisingToken(advertisingToken));
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            var decrypted = client.DecryptData(encrypted.EncryptedData);
            Assert.Equal(DecryptionStatus.Success, decrypted.Status);
            Assert.Equal(data, decrypted.DecryptedData);
        }

        [Fact]
        public void EncryptDataSiteIdAndTokenSet()
        {
            byte[] data = { 1, 2, 3, 4, 5, 6 };
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            var advertisingToken = UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_EMAIL_UID, MASTER_KEY, SITE_ID, SITE_KEY, UID2TokenGenerator.DefaultParams);
            Assert.Throws<ArgumentException>(() =>
                client.EncryptData(EncryptionDataRequest.ForData(data).WithAdvertisingToken(advertisingToken).WithSiteId(SITE_KEY.SiteId)));
        }

        [Fact]
        public void EncryptDataTokenDecryptFailed()
        {
            byte[] data = { 1, 2, 3, 4, 5, 6};
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            var encrypted = client.EncryptData(EncryptionDataRequest.ForData(data).WithAdvertisingToken("bogus-token"));
            Assert.Equal(EncryptionStatus.TokenDecryptFailure, encrypted.Status);
        }

        [Fact]
        public void EncryptDataKeyExpired()
        {
            byte[] data = { 1, 2, 3, 4, 5, 6};
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            Key key = new Key(SITE_KEY_ID, SITE_ID, NOW, NOW, NOW.AddDays(-1), MakeTestSecret(9));
            client.RefreshJson(KeySetToJson(key));
            var encrypted = client.EncryptData(EncryptionDataRequest.ForData(data).WithKey(key));
            Assert.Equal(EncryptionStatus.KeyInactive, encrypted.Status);
        }
        
        [Fact]
        public void EncryptDataTokenDecryptKeyExpired()
        {
            byte[] data = { 1, 2, 3, 4, 5, 6};
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            Key key = new Key(SITE_KEY_ID, SITE_ID2, NOW, NOW, NOW.AddDays(-1), MakeTestSecret(9));
            client.RefreshJson(KeySetToJson(MASTER_KEY, key));
            string advertisingToken = UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_EMAIL_UID, MASTER_KEY, SITE_ID, key, UID2TokenGenerator.DefaultParams);
            var encrypted = client.EncryptData(EncryptionDataRequest.ForData(data).WithAdvertisingToken(advertisingToken));
            Assert.Equal(EncryptionStatus.NotAuthorizedForKey, encrypted.Status);
        }

        [Fact]
        public void EncryptDataKeyInactive()
        {
            byte[] data = { 1, 2, 3, 4, 5, 6 };
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            Key key = new Key(SITE_KEY_ID, SITE_ID, NOW, NOW.AddDays(1), NOW.AddDays(2), MakeTestSecret(9));
            client.RefreshJson(KeySetToJson(key));
            var encrypted = client.EncryptData(EncryptionDataRequest.ForData(data).WithKey(key));
            Assert.Equal(EncryptionStatus.KeyInactive, encrypted.Status);
        }

        [Fact]
        public void EncryptDataKeyExpiredCustomNow()
        {
            byte[] data = { 1, 2, 3, 4, 5, 6};
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            client.RefreshJson(KeySetToJson(SITE_KEY));
            var encrypted = client.EncryptData(EncryptionDataRequest.ForData(data).WithKey(SITE_KEY).WithNow(SITE_KEY.Expires));
            Assert.Equal(EncryptionStatus.KeyInactive, encrypted.Status);
        }

        [Fact]
        public void EncryptDataKeyInactiveCustomNow()
        {
            byte[] data = { 1, 2, 3, 4, 5, 6};
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            client.RefreshJson(KeySetToJson(SITE_KEY));
            var encrypted = client.EncryptData(EncryptionDataRequest.ForData(data).WithKey(SITE_KEY).WithNow(SITE_KEY.Activates.AddSeconds(-1)));
            Assert.Equal(EncryptionStatus.KeyInactive, encrypted.Status);
        }

        [Fact]
        public void EncryptDataNoSiteKey()
        {
            byte[] data = { 1, 2, 3, 4, 5, 6 };
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            client.RefreshJson(KeySetToJson(MASTER_KEY));
            var encrypted = client.EncryptData(EncryptionDataRequest.ForData(data).WithSiteId(205));
            Assert.Equal(EncryptionStatus.NotAuthorizedForKey, encrypted.Status);
        }

        [Fact]
        public void EncryptDataSiteKeyExpired()
        {
            byte[] data = { 1, 2, 3, 4, 5, 6};
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            Key key = new Key(SITE_KEY_ID, SITE_ID, NOW, NOW, NOW.AddDays(-1), MakeTestSecret(9));
            client.RefreshJson(KeySetToJson(MASTER_KEY, key));
            var encrypted = client.EncryptData(EncryptionDataRequest.ForData(data).WithSiteId(key.SiteId));
            Assert.Equal(EncryptionStatus.NotAuthorizedForKey, encrypted.Status);
        }

        [Fact]
        public void EncryptDataSiteKeyInactive()
        {
            byte[] data = { 1, 2, 3, 4, 5, 6};
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            Key key = new Key(SITE_KEY_ID, SITE_ID, NOW, NOW.AddDays(1), NOW.AddDays(2), MakeTestSecret(9));
            client.RefreshJson(KeySetToJson(MASTER_KEY, key));
            var encrypted = client.EncryptData(EncryptionDataRequest.ForData(data).WithSiteId(key.SiteId));
            Assert.Equal(EncryptionStatus.NotAuthorizedForKey, encrypted.Status);
        }

        [Fact]
        public void EncryptDataSiteKeyInactiveCustomNow()
        {
            byte[] data = { 1, 2, 3, 4, 5, 6 };
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            var encrypted = client.EncryptData(
                EncryptionDataRequest.ForData(data).WithSiteId(SITE_KEY.SiteId).WithNow(SITE_KEY.Activates.AddSeconds(-1)));
            Assert.Equal(EncryptionStatus.NotAuthorizedForKey, encrypted.Status);
        }

        [Fact]
        public void EncryptDataTokenExpired()
        {
            var expiry = NOW.AddSeconds(-60);
            var encryptParams = UID2TokenGenerator.DefaultParams.WithTokenExpiry(expiry);

            byte[] data = { 1, 2, 3, 4, 5, 6};
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            var advertisingToken = UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_EMAIL_UID, MASTER_KEY, SITE_ID, SITE_KEY, encryptParams);
            var encrypted = client.EncryptData(EncryptionDataRequest.ForData(data).WithAdvertisingToken(advertisingToken));
            Assert.Equal(EncryptionStatus.TokenDecryptFailure, encrypted.Status);

            var now = DateTimeUtils.FromEpochMilliseconds(DateTimeUtils.DateTimeToEpochMilliseconds(expiry.AddSeconds(-1)));
            encrypted = client.EncryptData(EncryptionDataRequest.ForData(data).WithAdvertisingToken(advertisingToken).WithNow(now));
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            var decrypted = client.DecryptData(encrypted.EncryptedData);
            Assert.Equal(DecryptionStatus.Success, decrypted.Status);
            Assert.Equal(data, decrypted.DecryptedData);
            Assert.Equal(now, decrypted.EncryptedAt);
        }

        [Fact]
        public void DecryptDataBadPayloadType()
        {
            byte[] data = { 1, 2, 3, 4, 5, 6 };
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            client.RefreshJson(KeySetToJson(SITE_KEY));
            var encrypted = client.EncryptData(EncryptionDataRequest.ForData(data).WithKey(SITE_KEY));
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            byte[] encryptedBytes = Convert.FromBase64String(encrypted.EncryptedData);
            encryptedBytes[0] = 0;
            var decrypted = client.DecryptData(Convert.ToBase64String(encryptedBytes));
            Assert.Equal(DecryptionStatus.InvalidPayloadType, decrypted.Status);
        }

        [Fact]
        public void DecryptDataBadVersion()
        {
            byte[] data = { 1, 2, 3, 4, 5, 6};
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            client.RefreshJson(KeySetToJson(SITE_KEY));
            var encrypted = client.EncryptData(EncryptionDataRequest.ForData(data).WithKey(SITE_KEY));
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            byte[] encryptedBytes = Convert.FromBase64String(encrypted.EncryptedData);
            encryptedBytes[1] = 0;
            var decrypted = client.DecryptData(Convert.ToBase64String(encryptedBytes));
            Assert.Equal(DecryptionStatus.VersionNotSupported, decrypted.Status);
        }

        [Fact]
        public void DecryptDataBadPayload()
        {
            byte[] data = { 1, 2, 3, 4, 5, 6 };
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            client.RefreshJson(KeySetToJson(SITE_KEY));
            var encrypted = client.EncryptData(EncryptionDataRequest.ForData(data).WithKey(SITE_KEY));
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            byte[] encryptedBytes = Convert.FromBase64String(encrypted.EncryptedData);

            byte[] encryptedBytesMod = new byte[encryptedBytes.Length + 1];
            Array.Copy(encryptedBytes, encryptedBytesMod, encryptedBytes.Length);
            var decrypted = client.DecryptData(Convert.ToBase64String(encryptedBytesMod));
            Assert.Equal(DecryptionStatus.InvalidPayload, decrypted.Status);

            encryptedBytesMod = new byte[encryptedBytes.Length - 2];
            Array.Copy(encryptedBytes, encryptedBytesMod, encryptedBytes.Length-2);
            decrypted = client.DecryptData(Convert.ToBase64String(encryptedBytesMod));
            Assert.Equal(DecryptionStatus.InvalidPayload, decrypted.Status);
        }

        [Fact]
        public void DecryptDataNoDecryptionKey()
        {
            byte[] data = { 1, 2, 3, 4, 5, 6};
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            client.RefreshJson(KeySetToJson(SITE_KEY));
            var encrypted = client.EncryptData(EncryptionDataRequest.ForData(data).WithKey(SITE_KEY));
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            client.RefreshJson(KeySetToJson(MASTER_KEY));
            var decrypted = client.DecryptData(encrypted.EncryptedData);
            Assert.Equal(DecryptionStatus.NotAuthorizedForKey, decrypted.Status);
        }


        private static string KeySetToJson(params Key[] keys)
        {
            return @"{""body"": [" + string.Join(",", keys.Select(k => $@"{{""id"": {k.Id},
                ""site_id"": {k.SiteId},
                ""created"": {DateTimeUtils.DateTimeToEpochSeconds(k.Created)},
                ""activates"": {DateTimeUtils.DateTimeToEpochSeconds(k.Activates)},
                ""expires"": {DateTimeUtils.DateTimeToEpochSeconds(k.Expires)},
                ""secret"": ""{Convert.ToBase64String(k.Secret)}""
                }}")) + "]}";
        }

        private static byte[] MakeTestSecret(byte value)
        {
            var ret = new byte[32];
            Array.Fill(ret, value);
            return ret;
        }
    }
}
