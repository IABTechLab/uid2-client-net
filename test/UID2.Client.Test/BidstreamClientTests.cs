using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using UID2.Client.Test.builder;
using UID2.Client.Utils;
using Xunit;
using static UID2.Client.Test.builder.AdvertisingTokenBuilder;
using static UID2.Client.Test.TestData;

namespace UID2.Client.Test
{
    public class BidstreamClientTests
    {
        private readonly BidstreamClient _client = new("endpoint", "authkey", CLIENT_SECRET);
        private readonly AdvertisingTokenBuilder _tokenBuilder = AdvertisingTokenBuilder.Builder().WithVersion(AdvertisingTokenBuilder.TokenVersion.V4);

        private static string KeyBidstreamResponse(IEnumerable<Key> keys, IdentityScope identityScope = IdentityScope.UID2)
        {
            var keyToJson = (Key key) => new
            {
                id = key.Id,
                created = DateTimeUtils.DateTimeToEpochSeconds(key.Created),
                activates = DateTimeUtils.DateTimeToEpochSeconds(key.Activates),
                expires = DateTimeUtils.DateTimeToEpochSeconds(key.Expires),
                secret = Convert.ToBase64String(key.Secret),
                unexpected_key_field = "123" //ensure new fields can be handled by old SDK versions
            };

            var json = JObject.FromObject(new
            {
                body = new
                {
                    max_bidstream_lifetime_seconds = TimeSpan.FromDays(3).TotalSeconds,
                    identity_scope = identityScope.ToString(),
                    allow_clock_skew_seconds = 1800, //30 mins
                    keys = keys.Select(keyToJson).ToArray(),
                    unexpected_header_field = "12345", //ensure new fields can be handled by old SDK versions
                    site_data = new[]
                    {
                        new
                        {
                            id = SITE_ID,
                            domain_names = new[] { "example.com", "example.org" },
                            unexpected_domain_field = "123" //ensure new fields can be handled by old SDK versions

                        },
                        new
                        {
                            id = SITE_ID2,
                            domain_names = new[] { "example.net", "example.edu" },
                            unexpected_domain_field = "123" //ensure new fields can be handled by old SDK versions
                        }
                    }
                }
            });

            return json.ToString();
        }

        private void Refresh(string json)
        {
            var refreshResult = _client.RefreshJson(json);
            Assert.True(refreshResult.Success);
        }

        [Theory]
        [InlineData(IdentityScope.UID2, TokenVersion.V2)]
        [InlineData(IdentityScope.EUID, TokenVersion.V2)]
        [InlineData(IdentityScope.UID2, TokenVersion.V3)]
        [InlineData(IdentityScope.EUID, TokenVersion.V3)]
        [InlineData(IdentityScope.UID2, TokenVersion.V4)]
        [InlineData(IdentityScope.EUID, TokenVersion.V4)]
        private void SmokeTestForBidstream(IdentityScope identityScope, TokenVersion tokenVersion)
        {
            Refresh(KeyBidstreamResponse(new[] { MASTER_KEY, SITE_KEY}, identityScope));

            var now = DateTime.UtcNow;
            var advertisingToken = AdvertisingTokenBuilder.Builder().WithVersion(tokenVersion).WithScope(identityScope).WithEstablished(now.AddMonths(-4)).WithGenerated(now.AddDays(-1)).WithExpiry(now.AddDays(2)).
                Build();
            DecryptAndAssertSuccess(advertisingToken, tokenVersion);
        }

        private void DecryptAndAssertSuccess(string advertisingToken, TokenVersion tokenVersion)
        {
            var res = _client.DecryptTokenIntoRawUid(advertisingToken, null);
            AssertSuccess(res, tokenVersion);
        }

        internal static void AssertSuccess(DecryptionResponse res, TokenVersion tokenVersion)
        {
            Assert.True(res.Success);
            Assert.Equal(EXAMPLE_EMAIL_RAW_UID2_V2, res.Uid);
            Assert.Equal((int)tokenVersion + 2, res.AdvertisingTokenVersion);
            if (tokenVersion != TokenVersion.V2)
                Assert.Equal(IdentityType.Email, res.IdentityType);
        }

        internal static void AssertFails(DecryptionResponse res, TokenVersion tokenVersion)
        {
            Assert.False(res.Success);
            Assert.Equal(DecryptionStatus.InvalidTokenLifetime, res.Status);
            Assert.Equal((int)tokenVersion + 2, res.AdvertisingTokenVersion);
            if (tokenVersion != TokenVersion.V2)
                Assert.Equal(IdentityType.Email, res.IdentityType);

        }


        [Theory]
        [InlineData(IdentityScope.UID2, TokenVersion.V3)]
        [InlineData(IdentityScope.EUID, TokenVersion.V3)]
        [InlineData(IdentityScope.UID2, TokenVersion.V4)]
        [InlineData(IdentityScope.EUID, TokenVersion.V4)]
        private void PhoneTest(IdentityScope identityScope, TokenVersion tokenVersion)
        {
            Refresh(KeyBidstreamResponse(new[] { MASTER_KEY, SITE_KEY }, identityScope));

            const string rawUidPhone = "BEOGxroPLdcY7LrSiwjY52+X05V0ryELpJmoWAyXiwbZ";
            var advertisingToken = AdvertisingTokenBuilder.Builder().WithVersion(tokenVersion).WithScope(identityScope).WithRawUid(rawUidPhone).Build();

            var res = _client.DecryptTokenIntoRawUid(advertisingToken, null);
            Assert.True(res.Success);
            Assert.Equal(rawUidPhone, res.Uid);
            Assert.Equal((int)tokenVersion + 2, res.AdvertisingTokenVersion);
            Assert.Equal(IdentityType.Phone, res.IdentityType);
        }

        [Theory]
        [InlineData(IdentityScope.UID2, TokenVersion.V2)]
        [InlineData(IdentityScope.EUID, TokenVersion.V2)]
        [InlineData(IdentityScope.UID2, TokenVersion.V3)]
        [InlineData(IdentityScope.EUID, TokenVersion.V3)]
        [InlineData(IdentityScope.UID2, TokenVersion.V4)]
        [InlineData(IdentityScope.EUID, TokenVersion.V4)]
        private void TokenLifetimeTooLongForBidstreamButRemainingLifetimeAllowed(IdentityScope identityScope, TokenVersion tokenVersion)
        {
            Refresh(KeyBidstreamResponse(new[] { MASTER_KEY, SITE_KEY }, identityScope));

            var generated = DateTime.UtcNow.AddDays(-1);
            var advertisingToken = AdvertisingTokenBuilder.Builder().WithVersion(tokenVersion).WithScope(identityScope).WithGenerated(generated).
                WithExpiry(generated.AddDays(3).AddMinutes(1)).Build();

            var res = _client.DecryptTokenIntoRawUid(advertisingToken, null);
            if (tokenVersion == TokenVersion.V2)
                AssertSuccess(res, tokenVersion);
            else
                AssertFails(res, tokenVersion);
        }

        [Theory]
        [InlineData(IdentityScope.UID2, TokenVersion.V2)]
        [InlineData(IdentityScope.EUID, TokenVersion.V2)]
        [InlineData(IdentityScope.UID2, TokenVersion.V3)]
        [InlineData(IdentityScope.EUID, TokenVersion.V3)]
        [InlineData(IdentityScope.UID2, TokenVersion.V4)]
        [InlineData(IdentityScope.EUID, TokenVersion.V4)]
        private void TokenRemainingLifetimeTooLongForBidstream(IdentityScope identityScope, TokenVersion tokenVersion)
        {
            Refresh(KeyBidstreamResponse(new[] { MASTER_KEY, SITE_KEY }, identityScope));

            var now = DateTime.UtcNow;
            var advertisingToken = AdvertisingTokenBuilder.Builder().WithVersion(tokenVersion).WithScope(identityScope).WithGenerated(now).
                WithExpiry(now.AddDays(3).AddMinutes(1)).Build();

            var res = _client.DecryptTokenIntoRawUid(advertisingToken, null);
            AssertFails(res, tokenVersion);
        }


        [Theory]
        //Note V2 does not have a "token generated" field, therefore v2 tokens can't have a future "token generated" date and are excluded from this test.
        [InlineData(IdentityScope.UID2, TokenVersion.V3)]
        [InlineData(IdentityScope.EUID, TokenVersion.V3)]
        [InlineData(IdentityScope.UID2, TokenVersion.V4)]
        [InlineData(IdentityScope.EUID, TokenVersion.V4)]
        private void TokenGeneratedInTheFutureToSimulateClockSkew(IdentityScope identityScope, TokenVersion tokenVersion)
        {
            Refresh(KeyBidstreamResponse(new[] { MASTER_KEY, SITE_KEY }, identityScope));

            var advertisingToken = AdvertisingTokenBuilder.Builder().WithVersion(tokenVersion).WithScope(identityScope).WithGenerated(DateTime.UtcNow.AddMinutes(31)).Build();

            var res = _client.DecryptTokenIntoRawUid(advertisingToken, null);
            AssertFails(res, tokenVersion);
        }


        [Theory]
        [InlineData(IdentityScope.UID2, TokenVersion.V2)]
        [InlineData(IdentityScope.EUID, TokenVersion.V2)]
        [InlineData(IdentityScope.UID2, TokenVersion.V3)]
        [InlineData(IdentityScope.EUID, TokenVersion.V3)]
        [InlineData(IdentityScope.UID2, TokenVersion.V4)]
        [InlineData(IdentityScope.EUID, TokenVersion.V4)]
        private void TokenGeneratedInTheFutureWithinAllowedClockSkew(IdentityScope identityScope, TokenVersion tokenVersion)
        {
            Refresh(KeyBidstreamResponse(new[] { MASTER_KEY, SITE_KEY }, identityScope));

            var advertisingToken = AdvertisingTokenBuilder.Builder().WithVersion(tokenVersion).WithScope(identityScope).WithGenerated(DateTime.UtcNow.AddMinutes(30)).Build();

            DecryptAndAssertSuccess(advertisingToken, tokenVersion);
        }

        [Theory]
        [InlineData(TokenVersion.V2)]
        [InlineData(TokenVersion.V3)]
        [InlineData(TokenVersion.V4)]
        private void LegacyResponseFromOldOperator(TokenVersion tokenVersion)
        {
            Refresh(TestData.KeySharingResponse(new[] { MASTER_KEY, SITE_KEY }));

            var advertisingToken = AdvertisingTokenBuilder.Builder().WithVersion(tokenVersion).Build();

            DecryptAndAssertSuccess(advertisingToken, tokenVersion);

        }


        [Theory]
        [InlineData(IdentityScope.UID2, TokenVersion.V2)]
        [InlineData(IdentityScope.EUID, TokenVersion.V2)]
        [InlineData(IdentityScope.UID2, TokenVersion.V3)]
        [InlineData(IdentityScope.EUID, TokenVersion.V3)]
        [InlineData(IdentityScope.UID2, TokenVersion.V4)]
        [InlineData(IdentityScope.EUID, TokenVersion.V4)]
        private void TokenGeneratedInTheFutureLegacyClient(IdentityScope identityScope, TokenVersion tokenVersion)
        {
            UID2Client client = new("endpoint", "authkey", CLIENT_SECRET, identityScope);

            var refreshResult = client.RefreshJson(KeyBidstreamResponse(new[] { MASTER_KEY, SITE_KEY }, identityScope));
            Assert.True(refreshResult.Success);

            var advertisingToken = AdvertisingTokenBuilder.Builder().WithVersion(tokenVersion).WithScope(identityScope).WithGenerated(DateTime.UtcNow.AddMinutes(31)).Build();

            var res = client.Decrypt(advertisingToken, null);
            AssertSuccess(res, tokenVersion);
        }

        [Theory]
        [InlineData(IdentityScope.UID2, TokenVersion.V2)]
        [InlineData(IdentityScope.EUID, TokenVersion.V2)]
        [InlineData(IdentityScope.UID2, TokenVersion.V3)]
        [InlineData(IdentityScope.EUID, TokenVersion.V3)]
        [InlineData(IdentityScope.UID2, TokenVersion.V4)]
        [InlineData(IdentityScope.EUID, TokenVersion.V4)]
        private void TokenLifetimeTooLongLegacyClient(IdentityScope identityScope, TokenVersion tokenVersion)
        {
            UID2Client client = new("endpoint", "authkey", CLIENT_SECRET, identityScope);

            var refreshResult = client.RefreshJson(KeyBidstreamResponse(new[] { MASTER_KEY, SITE_KEY }, identityScope));
            Assert.True(refreshResult.Success);

            var advertisingToken = AdvertisingTokenBuilder.Builder().WithVersion(tokenVersion).WithScope(identityScope).WithExpiry(DateTime.UtcNow.AddDays(3).AddMinutes(1)).Build();

            var res = client.Decrypt(advertisingToken, null);
            AssertSuccess(res, tokenVersion);
        }

        // tests below taken from EncryptionTestsV4.cs above "//  Sharing tests" comment (but excluding deprecated EncryptData/DecryptData methods) and modified to use BidstreamClient and the new JSON /key/bidstream response
        [Theory]
        [InlineData(EXAMPLE_EMAIL_RAW_UID2_V2, IdentityScope.UID2, IdentityType.Email)]
        [InlineData(EXAMPLE_PHONE_RAW_UID2_V3, IdentityScope.UID2, IdentityType.Phone)]
        [InlineData(EXAMPLE_EMAIL_RAW_UID2_V2, IdentityScope.EUID, IdentityType.Email)]
        [InlineData(EXAMPLE_PHONE_RAW_UID2_V3, IdentityScope.EUID, IdentityType.Phone)]
        private void IdentityScopeAndType_TestCases(String uid, IdentityScope identityScope, IdentityType? identityType)
        {
            var client = new BidstreamClient("ep", "ak", CLIENT_SECRET);
            var refreshResult = client.RefreshJson(KeyBidstreamResponse(new [] {MASTER_KEY, SITE_KEY}, identityScope));
            Assert.True(refreshResult.Success);

            string advertisingToken = identityScope == IdentityScope.UID2
                ? UID2TokenGenerator.GenerateUid2TokenV4(uid, MASTER_KEY, SITE_ID, SITE_KEY, UID2TokenGenerator.DefaultParams)
                : UID2TokenGenerator.GenerateEuidTokenV4(uid, MASTER_KEY, SITE_ID, SITE_KEY, UID2TokenGenerator.DefaultParams);
            var res = client.DecryptTokenIntoRawUid(advertisingToken, null, NOW);
            Assert.True(res.Success);
            Assert.Equal(uid, res.Uid);
            Assert.Equal(identityType, res.IdentityType);
            Assert.Equal(4, res.AdvertisingTokenVersion);
        }

        private static void ValidateAdvertisingToken(string advertisingTokenString, IdentityScope identityScope, IdentityType identityType, TokenVersion tokenVersion = TokenVersion.V4)
        {
            EncryptionTestsV4.ValidateAdvertisingToken(advertisingTokenString, identityScope, identityType, tokenVersion);
        }


        [Theory]
        [InlineData(TokenVersion.V2)]
        [InlineData(TokenVersion.V3)]
        [InlineData(TokenVersion.V4)]
        private void UserOptedOutTest(TokenVersion tokenVersion)
        {
            Refresh(KeyBidstreamResponse(new [] {MASTER_KEY, SITE_KEY}));

            var privacyBits = PrivacyBitsBuilder.Builder().WithOptedOut(true).Build();
            string advertisingToken = _tokenBuilder.WithPrivacyBits(privacyBits).WithVersion(tokenVersion).Build();
            ValidateAdvertisingToken(advertisingToken, IdentityScope.UID2, IdentityType.Email, tokenVersion);
            var res = _client.DecryptTokenIntoRawUid(advertisingToken, null);
            Assert.False(res.Success);
            Assert.Equal(DecryptionStatus.UserOptedOut, res.Status);
            Assert.Null(res.Uid);
        }

        [Theory]
        // These are the domain or app names associated with site SITE_ID, as defined by KeySharingResponse();
        [InlineData("example.com", TokenVersion.V2)]
        [InlineData("example.org", TokenVersion.V2)]
        [InlineData("com.123.Game.App.android", TokenVersion.V2)]
        [InlineData("example.com", TokenVersion.V3)]
        [InlineData("example.org", TokenVersion.V3)]
        [InlineData("com.123.Game.App.android", TokenVersion.V3)]
        [InlineData("example.com", TokenVersion.V4)]
        [InlineData("example.org", TokenVersion.V4)]
        [InlineData("com.123.Game.App.android", TokenVersion.V4)]
        private void TokenIsCstgDerivedTest(string domainOrAppName, TokenVersion tokenVersion)
        {
            Refresh(KeySharingResponse(new[] { MASTER_KEY, SITE_KEY }));

            var privacyBits = PrivacyBitsBuilder.Builder().WithClientSideGenerated(true).Build();
            string advertisingToken = _tokenBuilder.WithPrivacyBits(privacyBits).WithVersion(tokenVersion).Build();
            ValidateAdvertisingToken(advertisingToken, IdentityScope.UID2, IdentityType.Email, tokenVersion);
            var res = _client.DecryptTokenIntoRawUid(advertisingToken, domainOrAppName);
            Assert.True(res.IsClientSideGenerated);
            Assert.True(res.Success);
            Assert.Equal(DecryptionStatus.Success, res.Status);
            Assert.Equal(EXAMPLE_EMAIL_RAW_UID2_V2, res.Uid);
        }
        
        [Theory]
        // These are the domain or app names associated with site SITE_ID but vary in capitalization, as defined by KeySharingResponse();
        [InlineData("example.com", TokenVersion.V2)]
        [InlineData("example.org", TokenVersion.V2)]
        [InlineData("com.123.Game.App.android", TokenVersion.V2)]
        [InlineData("example.com", TokenVersion.V3)]
        [InlineData("example.org", TokenVersion.V3)]
        [InlineData("com.123.Game.App.android", TokenVersion.V3)]
        [InlineData("example.com", TokenVersion.V4)]
        [InlineData("example.org", TokenVersion.V4)]
        [InlineData("com.123.Game.App.android", TokenVersion.V4)]
        private void DomainOrAppNameCaseSensitiveAndCheckFailedTest(string domainOrAppName, TokenVersion tokenVersion)
        {
            Refresh(KeySharingResponse(new[] { MASTER_KEY, SITE_KEY }));

            var privacyBits = PrivacyBitsBuilder.Builder().WithClientSideGenerated(true).Build();
            string advertisingToken = _tokenBuilder.WithPrivacyBits(privacyBits).WithVersion(tokenVersion).Build();
            ValidateAdvertisingToken(advertisingToken, IdentityScope.UID2, IdentityType.Email, tokenVersion);
            var res = _client.DecryptTokenIntoRawUid(advertisingToken, domainOrAppName);
            Assert.True(res.IsClientSideGenerated);
            Assert.True(res.Success);
            Assert.Equal(DecryptionStatus.Success, res.Status);
            Assert.Equal(EXAMPLE_EMAIL_RAW_UID2_V2, res.Uid);
        }

        [Theory]
        [InlineData((string)null, TokenVersion.V2)]
        [InlineData("", TokenVersion.V2)]
        [InlineData("example.net", TokenVersion.V2)] // Domain associated with site SITE_ID2, as defined by KeySharingResponse().
        [InlineData("example.edu", TokenVersion.V2)] // Domain associated with site SITE_ID2, as defined by KeySharingResponse().
        [InlineData("com.123.Game.App.ios", TokenVersion.V2)] // App associated with site SITE_ID2, as defined by KeySharingResponse().
        [InlineData("foo.com", TokenVersion.V2)]     // Domain not associated with any site.
        [InlineData((string)null, TokenVersion.V3)]
        [InlineData("", TokenVersion.V3)]
        [InlineData("example.net", TokenVersion.V3)] // Domain associated with site SITE_ID2, as defined by KeySharingResponse().
        [InlineData("example.edu", TokenVersion.V3)] // Domain associated with site SITE_ID2, as defined by KeySharingResponse().
        [InlineData("com.123.Game.App.ios", TokenVersion.V3)] // App associated with site SITE_ID2, as defined by KeySharingResponse().
        [InlineData("foo.com", TokenVersion.V3)]     // Domain not associated with any site.
        [InlineData((string)null, TokenVersion.V4)]
        [InlineData("", TokenVersion.V4)]
        [InlineData("example.net", TokenVersion.V4)] // Domain associated with site SITE_ID2, as defined by KeySharingResponse().
        [InlineData("example.edu", TokenVersion.V4)] // Domain associated with site SITE_ID2, as defined by KeySharingResponse().
        [InlineData("com.123.Game.App.ios", TokenVersion.V4)] // App associated with site SITE_ID2, as defined by KeySharingResponse().
        [InlineData("foo.com", TokenVersion.V4)]     // Domain not associated with any site.
        private void TokenIsCstgDerivedDomainOrAppNameFailTest(string domainOrAppName, TokenVersion tokenVersion)
        {
            Refresh(KeySharingResponse(new[] { MASTER_KEY, SITE_KEY }));
            var privacyBits = PrivacyBitsBuilder.Builder().WithClientSideGenerated(true).Build();
            var advertisingToken = _tokenBuilder.WithPrivacyBits(privacyBits).WithVersion(tokenVersion).Build();
            var res = _client.DecryptTokenIntoRawUid(advertisingToken, domainOrAppName);
            Assert.True(res.IsClientSideGenerated);
            Assert.False(res.Success);
            Assert.Equal(DecryptionStatus.DomainOrAppNameCheckFailed, res.Status);
            Assert.Null(res.Uid);
        }

        [Theory]
        // Any domain or app name is OK, because the token is not client-side generated.
        [InlineData((string)null, TokenVersion.V2)]
        [InlineData("", TokenVersion.V2)]
        [InlineData("example.com", TokenVersion.V2)]
        [InlineData("foo.com", TokenVersion.V2)]
        [InlineData("com.uid2.devapp", TokenVersion.V2)]
        [InlineData((string)null, TokenVersion.V3)]
        [InlineData("", TokenVersion.V3)]
        [InlineData("example.com", TokenVersion.V3)]
        [InlineData("foo.com", TokenVersion.V3)]
        [InlineData("com.uid2.devapp", TokenVersion.V3)]
        [InlineData((string)null, TokenVersion.V4)]
        [InlineData("", TokenVersion.V4)]
        [InlineData("example.com", TokenVersion.V4)]
        [InlineData("foo.com", TokenVersion.V4)]
        [InlineData("com.uid2.devapp", TokenVersion.V4)]
        private void TokenIsNotCstgDerivedDomainNameSuccessTest(string domainOrAppName, TokenVersion tokenVersion)
        {
            Refresh(KeySharingResponse(new[] { MASTER_KEY, SITE_KEY }));
            var privacyBits = PrivacyBitsBuilder.Builder().WithClientSideGenerated(false).Build();
            string advertisingToken = _tokenBuilder.WithPrivacyBits(privacyBits).WithVersion(tokenVersion).Build();
            ValidateAdvertisingToken(advertisingToken, IdentityScope.UID2, IdentityType.Email, tokenVersion);
            var res = _client.DecryptTokenIntoRawUid(advertisingToken, domainOrAppName);
            Assert.False(res.IsClientSideGenerated);
            Assert.True(res.Success);
            Assert.Equal(DecryptionStatus.Success, res.Status);
            Assert.Equal(EXAMPLE_EMAIL_RAW_UID2_V2, res.Uid);
        }

        [Fact]
        public void EmptyKeyContainer()
        {
            string advertisingToken = _tokenBuilder.Build();
            ValidateAdvertisingToken(advertisingToken, IdentityScope.UID2, IdentityType.Email);
            var res = _client.DecryptTokenIntoRawUid(advertisingToken, null);
            Assert.False(res.Success);
            Assert.Equal(DecryptionStatus.NotInitialized, res.Status);
        }

        [Fact]
        public void ExpiredKeyContainer()
        {
            string advertisingToken = _tokenBuilder.Build();
            ValidateAdvertisingToken(advertisingToken, IdentityScope.UID2, IdentityType.Email);

            Key masterKeyExpired = new Key(MASTER_KEY_ID, -1, NOW, NOW.AddHours(-2), NOW.AddHours(-1), MASTER_SECRET);
            Key siteKeyExpired = new Key(SITE_KEY_ID, SITE_ID, NOW, NOW.AddHours(-2), NOW.AddHours(-1), SITE_SECRET);
            Refresh(KeyBidstreamResponse(new[] { masterKeyExpired, siteKeyExpired}));

            var res = _client.DecryptTokenIntoRawUid(advertisingToken, null);
            Assert.False(res.Success);
            Assert.Equal(DecryptionStatus.KeysNotSynced, res.Status);
        }

        [Fact]
        public void NotAuthorizedForMasterKey()
        {
            Key anotherMasterKey = new Key(MASTER_KEY_ID + SITE_KEY_ID + 1, -1, NOW, NOW, NOW.AddHours(1), MASTER_SECRET);
            Key anotherSiteKey = new Key(MASTER_KEY_ID + SITE_KEY_ID + 2, SITE_ID, NOW, NOW, NOW.AddHours(1), SITE_SECRET);
            Refresh(KeyBidstreamResponse(new[] { anotherMasterKey, anotherSiteKey}));

            var res = _client.DecryptTokenIntoRawUid(_tokenBuilder.Build(), null);
            Assert.Equal(DecryptionStatus.NotAuthorizedForMasterKey, res.Status);
        }

        [Fact]
        public void InvalidPayload()
        {
            byte[] payload = UID2Base64UrlCoder.Decode(_tokenBuilder.Build());
            var advertisingToken = UID2Base64UrlCoder.Encode(payload.SkipLast(1).ToArray());
            ValidateAdvertisingToken(advertisingToken, IdentityScope.UID2, IdentityType.Email);

            Refresh(KeyBidstreamResponse(new[] { MASTER_KEY, SITE_KEY}));

            var res = _client.DecryptTokenIntoRawUid(advertisingToken, null);
            Assert.Equal(DecryptionStatus.InvalidPayload, res.Status);
        }

        [Fact]
        public void TokenExpiryAndCustomNow()
        {
            var expiry = NOW.AddDays(-60);
            Refresh(KeyBidstreamResponse(new[] { MASTER_KEY, SITE_KEY}));
            string advertisingToken = _tokenBuilder.WithGenerated(expiry.AddSeconds(-60)).WithExpiry(expiry).Build();
            ValidateAdvertisingToken(advertisingToken, IdentityScope.UID2, IdentityType.Email);

            var res = _client.DecryptTokenIntoRawUid(advertisingToken, null, expiry.AddSeconds(1));
            Assert.Equal(DecryptionStatus.ExpiredToken, res.Status);

            res = _client.DecryptTokenIntoRawUid(advertisingToken, null, expiry.AddSeconds(-1));
            Assert.Equal(EXAMPLE_EMAIL_RAW_UID2_V2, res.Uid);
        }

    }
}
