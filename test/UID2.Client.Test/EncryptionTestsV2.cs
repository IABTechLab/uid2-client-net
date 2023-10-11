using System;
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
        private readonly AdvertisingTokenBuilder _tokenBuilder = AdvertisingTokenBuilder.Builder().WithVersion(AdvertisingTokenBuilder.TokenVersion.V2);

        [Fact]
        public void SmokeTest()
        {
            var refreshResult = _client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            Assert.True(refreshResult.Success);
            var res = _client.Decrypt(_tokenBuilder.Build(), NOW);
            Assert.True(res.Success);
            Assert.Equal(EXAMPLE_UID, res.Uid);
        }

        [Fact]
        public void UserOptedOutTest()
        {
            _client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            var privacyBits = PrivacyBitsBuilder.Builder().WithOptedOut(true).Build();
            var advertisingToken = _tokenBuilder.WithPrivacyBits(privacyBits).Build();
            var res = _client.Decrypt(advertisingToken, NOW);
            Assert.False(res.Success);
            Assert.Equal(DecryptionStatus.UserOptedOut, res.Status);
            Assert.Null(res.Uid);
        }

        [Theory]
        // These are the domains associated with site SITE_ID, as defined by KeySharingResponse();
        [InlineData("example.com")]
        [InlineData("example.org")]
        public void TokenIsCstgDerivedTest(string domainName)
        {
            _client.RefreshJson(KeySharingResponse(new [] { MASTER_KEY, SITE_KEY }));
            var privacyBits = PrivacyBitsBuilder.Builder().WithClientSideGenerated(true).Build();
            var advertisingToken = _tokenBuilder.WithPrivacyBits(privacyBits).Build();
            var res = _client.Decrypt(advertisingToken, domainName);
            Assert.True(res.IsClientSideGenerated);
            Assert.True(res.Success);
            Assert.Equal(DecryptionStatus.Success, res.Status);
            Assert.Equal(EXAMPLE_UID, res.Uid);
        }

        [Theory]
        [InlineData((string)null)]
        [InlineData("")]
        // Domains associated with site SITE_ID2, as defined by KeySharingResponse().
        [InlineData("example.net")]
        [InlineData("example.edu")]
        // Domain not associated with any site.
        [InlineData("foo.com")]
        public void TokenIsCstgDerivedDomainNameFailTest(string domainName)
        {
            _client.RefreshJson(KeySharingResponse(new [] { MASTER_KEY, SITE_KEY }));
            var privacyBits = PrivacyBitsBuilder.Builder().WithClientSideGenerated(true).Build();
            var advertisingToken = _tokenBuilder.WithPrivacyBits(privacyBits).Build();
            var res = _client.Decrypt(advertisingToken, domainName);
            Assert.True(res.IsClientSideGenerated);
            Assert.False(res.Success);
            Assert.Equal(DecryptionStatus.DomainNameCheckFailed, res.Status);
            Assert.Null(res.Uid);
        }
        
        // if there is domain name associated with sites but we explicitly call 
        // DecryptionResponse Decrypt(string token) or DecryptionResponse Decrypt(string token, DateTime utcNow)
        // and we do not want to do domain name check
        // the Decrypt function would still decrypt successfully
        // in case DSP does not want to enable domain name check
        [Fact]
        public void TokenIsCstgDerivedNoDomainNameTest()
        {
            _client.RefreshJson(KeySharingResponse(new [] { MASTER_KEY, SITE_KEY }));
            var privacyBits = PrivacyBitsBuilder.Builder().WithClientSideGenerated(true).Build();
            var advertisingToken = _tokenBuilder.WithPrivacyBits(privacyBits).Build();
            var res = _client.Decrypt(advertisingToken);
            Assert.True(res.IsClientSideGenerated);
            Assert.True(res.Success);
            Assert.Equal(DecryptionStatus.Success, res.Status);
            Assert.Equal(EXAMPLE_UID, res.Uid);
        }

        [Theory]
        // Any domain name is OK, because the token is not client-side generated.
        [InlineData((string) null)]
        [InlineData("")]
        [InlineData("example.com")]
        [InlineData("foo.com")]
        public void TokenIsNotCstgDerivedDomainNameSuccessTest(string domainName)
        {
            _client.RefreshJson(KeySharingResponse(new [] { MASTER_KEY, SITE_KEY }));
            var privacyBits = PrivacyBitsBuilder.Builder().WithClientSideGenerated(false).Build();
            var advertisingToken = _tokenBuilder.WithPrivacyBits(privacyBits).Build();
            var res = _client.Decrypt(advertisingToken, domainName);
            Assert.False(res.IsClientSideGenerated);
            Assert.True(res.Success);
            Assert.Equal(DecryptionStatus.Success, res.Status);
            Assert.Equal(EXAMPLE_UID, res.Uid);
        }

        [Fact]
        public void EmptyKeyContainer()
        {
            var res = _client.Decrypt(_tokenBuilder.Build(), NOW);
            Assert.False(res.Success);
            Assert.Equal(DecryptionStatus.NotInitialized, res.Status);
        }

        [Fact]
        public void ExpiredKeyContainer()
        {
            Key masterKeyExpired = new Key(MASTER_KEY_ID, -1, NOW, NOW.AddHours(-2), NOW.AddHours(-1), MASTER_SECRET);
            Key siteKeyExpired = new Key(SITE_KEY_ID, SITE_ID, NOW, NOW.AddHours(-2), NOW.AddHours(-1), SITE_SECRET);
            _client.RefreshJson(KeySetToJson(masterKeyExpired, siteKeyExpired));

            var res = _client.Decrypt(_tokenBuilder.Build(), NOW);
            Assert.False(res.Success);
            Assert.Equal(DecryptionStatus.KeysNotSynced, res.Status);
        }

        [Fact]
        public void NotAuthorizedForKey()
        {
            Key anotherMasterKey = new Key(MASTER_KEY_ID + SITE_KEY_ID + 1, -1, NOW, NOW, NOW.AddHours(1), MASTER_SECRET);
            Key anotherSiteKey = new Key(MASTER_KEY_ID + SITE_KEY_ID + 2, SITE_ID, NOW, NOW, NOW.AddHours(1), SITE_SECRET);
            _client.RefreshJson(KeySetToJson(anotherMasterKey, anotherSiteKey));

            var res = _client.Decrypt(_tokenBuilder.Build(), NOW);
            Assert.Equal(DecryptionStatus.NotAuthorizedForMasterKey, res.Status);
        }

        [Fact]
        public void InvalidPayload()
        {
            byte[] payload = Convert.FromBase64String(_tokenBuilder.Build());
            var advertisingToken = Convert.ToBase64String(payload.SkipLast(1).ToArray());

            _client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));

            var res = _client.Decrypt(advertisingToken, NOW);
            Assert.Equal(DecryptionStatus.InvalidPayload, res.Status);
        }

        [Fact]
        public void TokenExpiryAndCustomNow()
        {
            var expiry = NOW.AddDays(-60);

            _client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            var advertisingToken = _tokenBuilder.WithExpiry(expiry).Build();;

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