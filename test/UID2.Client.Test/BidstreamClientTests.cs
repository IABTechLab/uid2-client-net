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

        private static string KeyBidstreamResponse(IEnumerable<Key> keys, IdentityScope identityScope)
        {
            var keyToJson = (Key key) => new
            {
                id = key.Id,
                created = DateTimeUtils.DateTimeToEpochSeconds(key.Created),
                activates = DateTimeUtils.DateTimeToEpochSeconds(key.Activates),
                expires = DateTimeUtils.DateTimeToEpochSeconds(key.Expires),
                secret = Convert.ToBase64String(key.Secret),
            };

            var json = JObject.FromObject(new
            {
                body = new
                {
                    max_bidstream_lifetime_seconds = 3 * 24 * 60 * 60, //3 days
                    identity_scope = identityScope.ToString(),
                    allow_clock_skew_seconds = 1800, //30 mins
                    keys = keys.Select(keyToJson).ToArray(),
                    site_data = new[]
                    {
                        new
                        {
                            id = SITE_ID,
                            domain_names = new[] { "example.com", "example.org" }
                        },
                        new
                        {
                            id = SITE_ID2,
                            domain_names = new[] { "example.net", "example.edu" }
                        }
                    }
                }
            });

            return json.ToString();
        }

        [Theory]
        [InlineData(IdentityScope.UID2, TokenVersion.V2)]
        [InlineData(IdentityScope.EUID, TokenVersion.V2)]
        [InlineData(IdentityScope.UID2, TokenVersion.V3)]
        [InlineData(IdentityScope.EUID, TokenVersion.V3)]
        [InlineData(IdentityScope.UID2, TokenVersion.V4)]
        [InlineData(IdentityScope.EUID, TokenVersion.V4)]
        private void SmokeTest(IdentityScope identityScope, TokenVersion tokenVersion)
        {
            var refreshResult = _client.RefreshJson(KeyBidstreamResponse(new[] { MASTER_KEY, SITE_KEY}, identityScope));
            Assert.True(refreshResult.Success);

            var advertisingToken = AdvertisingTokenBuilder.Builder().WithVersion(tokenVersion).WithScope(identityScope).Build();
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
            var refreshResult = _client.RefreshJson(KeyBidstreamResponse(new[] { MASTER_KEY, SITE_KEY }, identityScope));
            Assert.True(refreshResult.Success);

            const string rawUidPhone = "BEOGxroPLdcY7LrSiwjY52+X05V0ryELpJmoWAyXiwbZ";
            var advertisingToken = AdvertisingTokenBuilder.Builder().WithVersion(tokenVersion).WithScope(identityScope).WithRawUid(rawUidPhone).Build();

            var res = _client.DecryptTokenIntoRawUid(advertisingToken, null);
            Assert.True(res.Success);
            Assert.Equal(rawUidPhone, res.Uid);
            Assert.Equal((int)tokenVersion + 2, res.AdvertisingTokenVersion);
            if (tokenVersion != TokenVersion.V2)
                Assert.Equal(IdentityType.Phone, res.IdentityType);
        }

        [Theory]
        [InlineData(IdentityScope.UID2, TokenVersion.V2)]
        [InlineData(IdentityScope.EUID, TokenVersion.V2)]
        [InlineData(IdentityScope.UID2, TokenVersion.V3)]
        [InlineData(IdentityScope.EUID, TokenVersion.V3)]
        [InlineData(IdentityScope.UID2, TokenVersion.V4)]
        [InlineData(IdentityScope.EUID, TokenVersion.V4)]
        private void TokenLifetimeTooLongForBidstream(IdentityScope identityScope, TokenVersion tokenVersion)
        {
            var refreshResult = _client.RefreshJson(KeyBidstreamResponse(new[] { MASTER_KEY, SITE_KEY }, identityScope));
            Assert.True(refreshResult.Success);

            var advertisingToken = AdvertisingTokenBuilder.Builder().WithVersion(tokenVersion).WithScope(identityScope).WithExpiry(DateTime.UtcNow.AddDays(3).AddMinutes(1)).Build();

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
        private void TokenGeneratedInTheFuture(IdentityScope identityScope, TokenVersion tokenVersion)
        {
            var refreshResult = _client.RefreshJson(KeyBidstreamResponse(new[] { MASTER_KEY, SITE_KEY }, identityScope));
            Assert.True(refreshResult.Success);

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
        private void TokenGeneratedInTheFutureWithinAllowedSkew(IdentityScope identityScope, TokenVersion tokenVersion)
        {
            var refreshResult = _client.RefreshJson(KeyBidstreamResponse(new[] { MASTER_KEY, SITE_KEY }, identityScope));
            Assert.True(refreshResult.Success);

            var advertisingToken = AdvertisingTokenBuilder.Builder().WithVersion(tokenVersion).WithScope(identityScope).WithGenerated(DateTime.UtcNow.AddMinutes(30)).Build();

            DecryptAndAssertSuccess(advertisingToken, tokenVersion);
        }

        [Theory]
        [InlineData(TokenVersion.V2)]
        [InlineData(TokenVersion.V3)]
        [InlineData(TokenVersion.V4)]
        private void LegacyResponseFromOldOperator(TokenVersion tokenVersion)
        {
            var refreshResult = _client.RefreshJson(TestData.KeySharingResponse(new[] { MASTER_KEY, SITE_KEY }));
            Assert.True(refreshResult.Success);

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



    }
}
