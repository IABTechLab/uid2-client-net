using System;
using System.Linq;
using uid2_client.test.builder;
using UID2.Client.Utils;
using Xunit;
using static uid2_client.test.TestData;

namespace UID2.Client.Test
{
    public class EncryptionTestsV3
    {
        private readonly UID2Client _client = new("endpoint", "authkey", CLIENT_SECRET, IdentityScope.UID2);

        [Fact]
        public void SmokeTest()
        {
            var refreshResult = _client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            Assert.True(refreshResult.Success);
            string advertisingToken = UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY,
                UID2TokenGenerator.DefaultParams);
            var res = _client.Decrypt(advertisingToken, NOW);
            Assert.True(res.Success);
            Assert.Equal(EXAMPLE_UID, res.Uid);
        }

        [Fact]
        public void UserOptedOutTest()
        {
            _client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            var privacyBits = PrivacyBitsBuilder.Builder().WithOptedOut(true).Build();
            var tokenGeneratorParams = UID2TokenGenerator.DefaultParams.WithPrivacyBits(privacyBits);
            var advertisingToken =
                UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY,
                    tokenGeneratorParams);
            var res = _client.Decrypt(advertisingToken, NOW);
            Assert.False(res.Success);
            Assert.Equal(DecryptionStatus.UserOptedOut, res.Status);
            Assert.Null(res.Uid);
        }

        [Fact]
        public void TokenIsCstgDerivedTest()
        {
            _client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            var privacyBits = PrivacyBitsBuilder.Builder().WithCstgDerived(true).Build();
            var advertisingToken = UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY,
                UID2TokenGenerator.DefaultParams.WithPrivacyBits(privacyBits));
            var res = _client.Decrypt(advertisingToken, NOW);
            Assert.True(res.IsCstgDerived);
            Assert.True(res.Success);
            Assert.Equal(DecryptionStatus.Success, res.Status);
            Assert.Equal(EXAMPLE_UID, res.Uid);
        }

        [Fact]
        public void TokenIsNotCstgDerivedTest()
        {
            _client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            var privacyBits = PrivacyBitsBuilder.Builder().WithCstgDerived(false).Build();
            var advertisingToken = UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY,
                UID2TokenGenerator.DefaultParams.WithPrivacyBits(privacyBits));
            var res = _client.Decrypt(advertisingToken, NOW);
            Assert.False(res.IsCstgDerived);
            Assert.True(res.Success);
            Assert.Equal(DecryptionStatus.Success, res.Status);
            Assert.Equal(EXAMPLE_UID, res.Uid);
        }

        [Fact]
        public void EmptyKeyContainer()
        {
            var advertisingToken = UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY,
                UID2TokenGenerator.DefaultParams);
            var res = _client.Decrypt(advertisingToken, NOW);
            Assert.False(res.Success);
            Assert.Equal(DecryptionStatus.NotInitialized, res.Status);
        }

        [Fact]
        public void ExpiredKeyContainer()
        {
            var advertisingToken = UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY,
                UID2TokenGenerator.DefaultParams);

            Key masterKeyExpired = new Key(MASTER_KEY_ID, -1, NOW, NOW.AddHours(-2), NOW.AddHours(-1), MASTER_SECRET);
            Key siteKeyExpired = new Key(SITE_KEY_ID, SITE_ID, NOW, NOW.AddHours(-2), NOW.AddHours(-1), SITE_SECRET);
            _client.RefreshJson(KeySetToJson(masterKeyExpired, siteKeyExpired));

            var res = _client.Decrypt(advertisingToken, NOW);
            Assert.False(res.Success);
            Assert.Equal(DecryptionStatus.KeysNotSynced, res.Status);
        }

        [Fact]
        public void NotAuthorizedForKey()
        {
            var advertisingToken = UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY,
                UID2TokenGenerator.DefaultParams);

            Key anotherMasterKey =
                new Key(MASTER_KEY_ID + SITE_KEY_ID + 1, -1, NOW, NOW, NOW.AddHours(1), MASTER_SECRET);
            Key anotherSiteKey = new Key(MASTER_KEY_ID + SITE_KEY_ID + 2, SITE_ID, NOW, NOW, NOW.AddHours(1),
                SITE_SECRET);
            _client.RefreshJson(KeySetToJson(anotherMasterKey, anotherSiteKey));

            var res = _client.Decrypt(advertisingToken, NOW);
            Assert.Equal(DecryptionStatus.NotAuthorizedForMasterKey, res.Status);
        }

        [Fact]
        public void InvalidPayload()
        {
            byte[] payload = Convert.FromBase64String(UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_UID, MASTER_KEY,
                SITE_ID, SITE_KEY, UID2TokenGenerator.DefaultParams));
            var advertisingToken = Convert.ToBase64String(payload.SkipLast(1).ToArray());

            _client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));

            var res = _client.Decrypt(advertisingToken, NOW);
            Assert.Equal(DecryptionStatus.InvalidPayload, res.Status);
        }

        [Fact]
        public void TokenExpiryAndCustomNow()
        {
            var expiry = NOW.AddDays(-60);
            var encryptParams = UID2TokenGenerator.DefaultParams.WithTokenExpiry(expiry);

            _client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            var advertisingToken =
                UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY, encryptParams);

            var res = _client.Decrypt(advertisingToken, expiry.AddSeconds(1));
            Assert.Equal(DecryptionStatus.ExpiredToken, res.Status);

            res = _client.Decrypt(advertisingToken, expiry.AddSeconds(-1));
            Assert.Equal(EXAMPLE_UID, res.Uid);
        }

        [Fact]
        public void EncryptDataSpecificKeyAndIv()
        {
            byte[] iv = new byte[12];
            var encrypted =
                _client.EncryptData(EncryptionDataRequest.ForData(SOME_DATA).WithKey(SITE_KEY)
                    .WithInitializationVector(iv));
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            _client.RefreshJson(KeySetToJson(SITE_KEY));
            var decrypted = _client.DecryptData(encrypted.EncryptedData);
            Assert.Equal(DecryptionStatus.Success, decrypted.Status);
            Assert.Equal(SOME_DATA, decrypted.DecryptedData);
        }

        [Fact]
        public void EncryptDataSpecificKeyAndGeneratedIv()
        {
            var encrypted = _client.EncryptData(EncryptionDataRequest.ForData(SOME_DATA).WithKey(SITE_KEY));
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            _client.RefreshJson(KeySetToJson(SITE_KEY));
            var decrypted = _client.DecryptData(encrypted.EncryptedData);
            Assert.Equal(DecryptionStatus.Success, decrypted.Status);
            Assert.Equal(SOME_DATA, decrypted.DecryptedData);
        }

        [Fact]
        public void EncryptDataSpecificSiteId()
        {
            _client.RefreshJson(KeySetToJson(SITE_KEY));
            var encrypted = _client.EncryptData(EncryptionDataRequest.ForData(SOME_DATA).WithSiteId(SITE_KEY.SiteId));
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            var decrypted = _client.DecryptData(encrypted.EncryptedData);
            Assert.Equal(DecryptionStatus.Success, decrypted.Status);
            Assert.Equal(SOME_DATA, decrypted.DecryptedData);
        }

        [Fact]
        public void EncryptDataSiteIdFromToken()
        {
            _client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            string advertisingToken = UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY,
                UID2TokenGenerator.DefaultParams);
            var encrypted =
                _client.EncryptData(EncryptionDataRequest.ForData(SOME_DATA).WithAdvertisingToken(advertisingToken));
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            var decrypted = _client.DecryptData(encrypted.EncryptedData);
            Assert.Equal(DecryptionStatus.Success, decrypted.Status);
            Assert.Equal(SOME_DATA, decrypted.DecryptedData);
        }

        [Fact]
        public void EncryptDataSiteIdFromTokenCustomSiteKeySiteId()
        {
            _client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            string advertisingToken = UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_UID, MASTER_KEY, SITE_ID2,
                SITE_KEY, UID2TokenGenerator.DefaultParams);
            var encrypted =
                _client.EncryptData(EncryptionDataRequest.ForData(SOME_DATA).WithAdvertisingToken(advertisingToken));
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            var decrypted = _client.DecryptData(encrypted.EncryptedData);
            Assert.Equal(DecryptionStatus.Success, decrypted.Status);
            Assert.Equal(SOME_DATA, decrypted.DecryptedData);
        }

        [Fact]
        public void EncryptDataSiteIdAndTokenSet()
        {
            _client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            var advertisingToken = UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY,
                UID2TokenGenerator.DefaultParams);
            Assert.Throws<ArgumentException>(() =>
                _client.EncryptData(EncryptionDataRequest.ForData(SOME_DATA).WithAdvertisingToken(advertisingToken)
                    .WithSiteId(SITE_KEY.SiteId)));
        }

        [Fact]
        public void EncryptDataTokenDecryptFailed()
        {
            _client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            var encrypted =
                _client.EncryptData(EncryptionDataRequest.ForData(SOME_DATA).WithAdvertisingToken("bogus-token"));
            Assert.Equal(EncryptionStatus.TokenDecryptFailure, encrypted.Status);
        }

        [Fact]
        public void EncryptDataKeyExpired()
        {
            Key key = new Key(SITE_KEY_ID, SITE_ID, NOW, NOW, YESTERDAY, TEST_SECRET);
            _client.RefreshJson(KeySetToJson(key));
            var encrypted = _client.EncryptData(EncryptionDataRequest.ForData(SOME_DATA).WithKey(key));
            Assert.Equal(EncryptionStatus.KeyInactive, encrypted.Status);
        }

        [Fact]
        public void EncryptDataTokenDecryptKeyExpired()
        {
            Key key = new Key(SITE_KEY_ID, SITE_ID2, NOW, NOW, YESTERDAY, TEST_SECRET);
            _client.RefreshJson(KeySetToJson(MASTER_KEY, key));
            string advertisingToken = UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_UID, MASTER_KEY, SITE_ID, key,
                UID2TokenGenerator.DefaultParams);
            var encrypted =
                _client.EncryptData(EncryptionDataRequest.ForData(SOME_DATA).WithAdvertisingToken(advertisingToken));
            Assert.Equal(EncryptionStatus.NotAuthorizedForKey, encrypted.Status);
        }

        [Fact]
        public void EncryptDataKeyInactive()
        {
            Key key = new Key(SITE_KEY_ID, SITE_ID, NOW, TOMORROW, IN_2_DAYS, TEST_SECRET);
            _client.RefreshJson(KeySetToJson(key));
            var encrypted = _client.EncryptData(EncryptionDataRequest.ForData(SOME_DATA).WithKey(key));
            Assert.Equal(EncryptionStatus.KeyInactive, encrypted.Status);
        }

        [Fact]
        public void EncryptDataKeyExpiredCustomNow()
        {
            _client.RefreshJson(KeySetToJson(SITE_KEY));
            var encrypted =
                _client.EncryptData(
                    EncryptionDataRequest.ForData(SOME_DATA).WithKey(SITE_KEY).WithNow(SITE_KEY.Expires));
            Assert.Equal(EncryptionStatus.KeyInactive, encrypted.Status);
        }

        [Fact]
        public void EncryptDataKeyInactiveCustomNow()
        {
            _client.RefreshJson(KeySetToJson(SITE_KEY));
            var encrypted = _client.EncryptData(EncryptionDataRequest.ForData(SOME_DATA).WithKey(SITE_KEY)
                .WithNow(SITE_KEY.Activates.AddSeconds(-1)));
            Assert.Equal(EncryptionStatus.KeyInactive, encrypted.Status);
        }

        [Fact]
        public void EncryptDataNoSiteKey()
        {
            _client.RefreshJson(KeySetToJson(MASTER_KEY));
            var encrypted = _client.EncryptData(EncryptionDataRequest.ForData(SOME_DATA).WithSiteId(205));
            Assert.Equal(EncryptionStatus.NotAuthorizedForKey, encrypted.Status);
        }

        [Fact]
        public void EncryptDataSiteKeyExpired()
        {
            Key key = new Key(SITE_KEY_ID, SITE_ID, NOW, NOW, YESTERDAY, TEST_SECRET);
            _client.RefreshJson(KeySetToJson(MASTER_KEY, key));
            var encrypted = _client.EncryptData(EncryptionDataRequest.ForData(SOME_DATA).WithSiteId(key.SiteId));
            Assert.Equal(EncryptionStatus.NotAuthorizedForKey, encrypted.Status);
        }

        [Fact]
        public void EncryptDataSiteKeyInactive()
        {
            Key key = new Key(SITE_KEY_ID, SITE_ID, NOW, TOMORROW, IN_2_DAYS, TEST_SECRET);
            _client.RefreshJson(KeySetToJson(MASTER_KEY, key));
            var encrypted = _client.EncryptData(EncryptionDataRequest.ForData(SOME_DATA).WithSiteId(key.SiteId));
            Assert.Equal(EncryptionStatus.NotAuthorizedForKey, encrypted.Status);
        }

        [Fact]
        public void EncryptDataSiteKeyInactiveCustomNow()
        {
            _client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            var encrypted = _client.EncryptData(
                EncryptionDataRequest.ForData(SOME_DATA).WithSiteId(SITE_KEY.SiteId)
                    .WithNow(SITE_KEY.Activates.AddSeconds(-1)));
            Assert.Equal(EncryptionStatus.NotAuthorizedForKey, encrypted.Status);
        }

        [Fact]
        public void EncryptDataTokenExpired()
        {
            var expiry = NOW.AddSeconds(-60);
            var encryptParams = UID2TokenGenerator.DefaultParams.WithTokenExpiry(expiry);

            _client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            var advertisingToken =
                UID2TokenGenerator.GenerateUid2TokenV3(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY, encryptParams);
            var encrypted =
                _client.EncryptData(EncryptionDataRequest.ForData(SOME_DATA).WithAdvertisingToken(advertisingToken));
            Assert.Equal(EncryptionStatus.TokenDecryptFailure, encrypted.Status);

            var now = DateTimeUtils.FromEpochMilliseconds(
                DateTimeUtils.DateTimeToEpochMilliseconds(expiry.AddSeconds(-1)));
            encrypted = _client.EncryptData(EncryptionDataRequest.ForData(SOME_DATA)
                .WithAdvertisingToken(advertisingToken)
                .WithNow(now));
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            var decrypted = _client.DecryptData(encrypted.EncryptedData);
            Assert.Equal(DecryptionStatus.Success, decrypted.Status);
            Assert.Equal(SOME_DATA, decrypted.DecryptedData);
            Assert.Equal(now, decrypted.EncryptedAt);
        }

        [Fact]
        public void DecryptDataBadPayloadType()
        {
            _client.RefreshJson(KeySetToJson(SITE_KEY));
            var encrypted = _client.EncryptData(EncryptionDataRequest.ForData(SOME_DATA).WithKey(SITE_KEY));
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            byte[] encryptedBytes = Convert.FromBase64String(encrypted.EncryptedData);
            encryptedBytes[0] = 0;
            var decrypted = _client.DecryptData(Convert.ToBase64String(encryptedBytes));
            Assert.Equal(DecryptionStatus.InvalidPayloadType, decrypted.Status);
        }

        [Fact]
        public void DecryptDataBadVersion()
        {
            _client.RefreshJson(KeySetToJson(SITE_KEY));
            var encrypted = _client.EncryptData(EncryptionDataRequest.ForData(SOME_DATA).WithKey(SITE_KEY));
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            byte[] encryptedBytes = Convert.FromBase64String(encrypted.EncryptedData);
            encryptedBytes[1] = 0;
            var decrypted = _client.DecryptData(Convert.ToBase64String(encryptedBytes));
            Assert.Equal(DecryptionStatus.VersionNotSupported, decrypted.Status);
        }

        [Fact]
        public void DecryptDataBadPayload()
        {
            _client.RefreshJson(KeySetToJson(SITE_KEY));
            var encrypted = _client.EncryptData(EncryptionDataRequest.ForData(SOME_DATA).WithKey(SITE_KEY));
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            byte[] encryptedBytes = Convert.FromBase64String(encrypted.EncryptedData);

            byte[] encryptedBytesMod = new byte[encryptedBytes.Length + 1];
            Array.Copy(encryptedBytes, encryptedBytesMod, encryptedBytes.Length);
            var decrypted = _client.DecryptData(Convert.ToBase64String(encryptedBytesMod));
            Assert.Equal(DecryptionStatus.InvalidPayload, decrypted.Status);

            encryptedBytesMod = new byte[encryptedBytes.Length - 2];
            Array.Copy(encryptedBytes, encryptedBytesMod, encryptedBytes.Length - 2);
            decrypted = _client.DecryptData(Convert.ToBase64String(encryptedBytesMod));
            Assert.Equal(DecryptionStatus.InvalidPayload, decrypted.Status);
        }

        [Fact]
        public void DecryptDataNoDecryptionKey()
        {
            _client.RefreshJson(KeySetToJson(SITE_KEY));
            var encrypted = _client.EncryptData(EncryptionDataRequest.ForData(SOME_DATA).WithKey(SITE_KEY));
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            _client.RefreshJson(KeySetToJson(MASTER_KEY));
            var decrypted = _client.DecryptData(encrypted.EncryptedData);
            Assert.Equal(DecryptionStatus.NotAuthorizedForKey, decrypted.Status);
        }
    }
}