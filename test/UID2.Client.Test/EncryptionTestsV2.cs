﻿using System;
using System.Linq;
using uid2_client.test.builder;
using UID2.Client.Utils;
using Xunit;
using static uid2_client.test.TestData;

namespace UID2.Client.Test
{
    public class EncryptionTestsV2
    {
        private const int SiteId = 12345;
        private readonly UID2Client _client = new("endpoint", "authkey", CLIENT_SECRET, IdentityScope.UID2);

        [Fact]
        public void SmokeTest()
        {
            var refreshResult = _client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            Assert.True(refreshResult.Success);
            String advertisingToken =
                UID2TokenGenerator.GenerateUid2TokenV2(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY);
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
                UID2TokenGenerator.GenerateUid2TokenV2(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY,
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
            var advertisingToken = UID2TokenGenerator.GenerateUid2TokenV2(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY,
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
            var advertisingToken = UID2TokenGenerator.GenerateUid2TokenV2(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY,
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
            var advertisingToken = UID2TokenGenerator.GenerateUid2TokenV2(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY);
            var res = _client.Decrypt(advertisingToken, NOW);
            Assert.False(res.Success);
            Assert.Equal(DecryptionStatus.NotInitialized, res.Status);
        }

        [Fact]
        public void ExpiredKeyContainer()
        {
            var advertisingToken = UID2TokenGenerator.GenerateUid2TokenV2(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY);

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
            var advertisingToken = UID2TokenGenerator.GenerateUid2TokenV2(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY);

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
            byte[] payload =
                Convert.FromBase64String(
                    UID2TokenGenerator.GenerateUid2TokenV2(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY));
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
                UID2TokenGenerator.GenerateUid2TokenV2(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY, encryptParams);

            var res = _client.Decrypt(advertisingToken, expiry.AddSeconds(1));
            Assert.Equal(DecryptionStatus.ExpiredToken, res.Status);

            res = _client.Decrypt(advertisingToken, expiry.AddSeconds(-1));
            Assert.Equal(EXAMPLE_UID, res.Uid);
        }

        [Fact]
        public void DecryptData()
        {
            var now = DateTimeUtils.FromEpochMilliseconds(DateTimeUtils.DateTimeToEpochMilliseconds(NOW));
            var encrypted = UID2TokenGenerator.EncryptDataV2(SOME_DATA, SITE_KEY, SiteId, now);
            _client.RefreshJson(KeySetToJson(SITE_KEY));
            var decrypted = _client.DecryptData(encrypted);
            Assert.Equal(DecryptionStatus.Success, decrypted.Status);
            Assert.Equal(SOME_DATA, decrypted.DecryptedData);
            Assert.Equal(now, decrypted.EncryptedAt);
        }

        [Fact]
        public void DecryptDataBadPayloadType()
        {
            var encrypted = UID2TokenGenerator.EncryptDataV2(SOME_DATA, SITE_KEY, SiteId, NOW);
            _client.RefreshJson(KeySetToJson(SITE_KEY));
            byte[] encryptedBytes = Convert.FromBase64String(encrypted);
            encryptedBytes[0] = 0;
            var decrypted = _client.DecryptData(Convert.ToBase64String(encryptedBytes));
            Assert.Equal(DecryptionStatus.InvalidPayloadType, decrypted.Status);
        }

        [Fact]
        public void DecryptDataBadVersion()
        {
            var encrypted = UID2TokenGenerator.EncryptDataV2(SOME_DATA, SITE_KEY, SiteId, NOW);
            _client.RefreshJson(KeySetToJson(SITE_KEY));
            byte[] encryptedBytes = Convert.FromBase64String(encrypted);
            encryptedBytes[1] = 0;
            var decrypted = _client.DecryptData(Convert.ToBase64String(encryptedBytes));
            Assert.Equal(DecryptionStatus.VersionNotSupported, decrypted.Status);
        }

        [Fact]
        public void DecryptDataBadPayload()
        {
            var encrypted = UID2TokenGenerator.EncryptDataV2(SOME_DATA, SITE_KEY, SiteId, NOW);
            _client.RefreshJson(KeySetToJson(SITE_KEY));
            byte[] encryptedBytes = Convert.FromBase64String(encrypted);

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
            var encrypted = UID2TokenGenerator.EncryptDataV2(SOME_DATA, SITE_KEY, SiteId, NOW);
            _client.RefreshJson(KeySetToJson(MASTER_KEY));
            var decrypted = _client.DecryptData(encrypted);
            Assert.Equal(DecryptionStatus.NotAuthorizedForKey, decrypted.Status);
        }
    }
}