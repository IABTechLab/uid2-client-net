using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using static UID2.Client.Test.builder.AdvertisingTokenBuilder;
using UID2.Client.Test.builder;
using UID2.Client.Utils;
using Xunit;
using static UID2.Client.Test.TestData;

namespace UID2.Client.Test
{
    public class SharingClientTests
    {
        private readonly SharingClient _client = new("endpoint", "authkey", CLIENT_SECRET);

        internal static string KeySharingResponse(IEnumerable<Key> keys, IdentityScope identityScope, int? callerSiteId = SITE_ID, int? defaultKeysetId = null, int? tokenExpirySeconds = null)
        {
            var keyToJson = (Key key) => new
            {
                id = key.Id,
                keyset_id = key.SiteId switch { -1 => 1, SITE_ID => 99999, _ => key.SiteId },
                created = DateTimeUtils.DateTimeToEpochSeconds(key.Created),
                activates = DateTimeUtils.DateTimeToEpochSeconds(key.Activates),
                expires = DateTimeUtils.DateTimeToEpochSeconds(key.Expires),
                secret = Convert.ToBase64String(key.Secret),
            };

            var json = JObject.FromObject(new
            {
                body = new
                {
                    caller_site_id = callerSiteId,
                    master_keyset_id = 1,
                    token_expiry_seconds = tokenExpirySeconds ?? 2592000,
                    identity_scope = identityScope.ToString(),
                    allow_clock_skew_seconds = 1800, //30 mins
                    max_sharing_lifetime_seconds = 30 * 24 * 60 * 60, //30 days
                    keys = keys.Select(keyToJson).ToArray()
                }
            });

            if (defaultKeysetId != null)
            {
                json["body"]["default_keyset_id"] = defaultKeysetId;
            }

            return json.ToString();
        }

        private void DecryptAndAssertSuccess(string advertisingToken, TokenVersion tokenVersion)
        {
            var res = _client.DecryptTokenIntoRawUid(advertisingToken);
            BidstreamClientTests.AssertSuccess(res, tokenVersion);
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
            var refreshResult = _client.RefreshJson(KeySharingResponse(new[] { MASTER_KEY, SITE_KEY }, identityScope));
            Assert.True(refreshResult.Success);

            var advertisingToken = AdvertisingTokenBuilder.Builder().WithVersion(tokenVersion).WithScope(identityScope).Build();

            DecryptAndAssertSuccess(advertisingToken, tokenVersion);
        }

        [Theory]
        [InlineData(IdentityScope.UID2, TokenVersion.V2)]
        [InlineData(IdentityScope.EUID, TokenVersion.V2)]
        [InlineData(IdentityScope.UID2, TokenVersion.V3)]
        [InlineData(IdentityScope.EUID, TokenVersion.V3)]
        [InlineData(IdentityScope.UID2, TokenVersion.V4)]
        [InlineData(IdentityScope.EUID, TokenVersion.V4)]
        private void TokenLifetimeTooLongForSharing(IdentityScope identityScope, TokenVersion tokenVersion)
        {
            var refreshResult = _client.RefreshJson(KeySharingResponse(new[] { MASTER_KEY, SITE_KEY }, identityScope));
            Assert.True(refreshResult.Success);

            var advertisingToken = AdvertisingTokenBuilder.Builder().WithVersion(tokenVersion).WithScope(identityScope).WithExpiry(DateTime.UtcNow.AddDays(31)).Build();

            var res = _client.DecryptTokenIntoRawUid(advertisingToken);
            BidstreamClientTests.AssertFails(res, tokenVersion);
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
            var refreshResult = _client.RefreshJson(KeySharingResponse(new[] { MASTER_KEY, SITE_KEY }, identityScope));
            Assert.True(refreshResult.Success);

            var advertisingToken = AdvertisingTokenBuilder.Builder().WithVersion(tokenVersion).WithScope(identityScope).WithGenerated(DateTime.UtcNow.AddMinutes(31)).Build();

            var res = _client.DecryptTokenIntoRawUid(advertisingToken);
            BidstreamClientTests.AssertFails(res, tokenVersion);
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
            var refreshResult = _client.RefreshJson(KeySharingResponse(new[] { MASTER_KEY, SITE_KEY }, identityScope));
            Assert.True(refreshResult.Success);

            var advertisingToken = AdvertisingTokenBuilder.Builder().WithVersion(tokenVersion).WithScope(identityScope).WithGenerated(DateTime.UtcNow.AddMinutes(30)).Build();

            DecryptAndAssertSuccess(advertisingToken, tokenVersion);
        }

        [Theory]
        [InlineData(IdentityScope.UID2, TokenVersion.V3)]
        [InlineData(IdentityScope.EUID, TokenVersion.V3)]
        [InlineData(IdentityScope.UID2, TokenVersion.V4)]
        [InlineData(IdentityScope.EUID, TokenVersion.V4)]
        private void PhoneTest(IdentityScope identityScope, TokenVersion tokenVersion)
        {
            var refreshResult = _client.RefreshJson(KeySharingResponse(new[] { MASTER_KEY, SITE_KEY }, identityScope));
            Assert.True(refreshResult.Success);

            const string rawUidPhone = "BEOGxroPLdcY7LrSiwjY52+X05V0ryELpJmoWAyXiwbZ";
            var advertisingToken = AdvertisingTokenBuilder.Builder().WithVersion(tokenVersion).WithScope(identityScope).WithRawUid(rawUidPhone).Build();

            var res = _client.DecryptTokenIntoRawUid(advertisingToken);
            Assert.True(res.Success);
            Assert.Equal(rawUidPhone, res.Uid);
            Assert.Equal((int)tokenVersion + 2, res.AdvertisingTokenVersion);
            if (tokenVersion != TokenVersion.V2)
                Assert.Equal(IdentityType.Phone, res.IdentityType);
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
        {   //similar to BidstreamClientTests.TokenGeneratedInTheFutureLegacyClient, but uses KeySharingResponse and Decrypt without domain parameter
            UID2Client client = new("endpoint", "authkey", CLIENT_SECRET, identityScope);

            var refreshResult = client.RefreshJson(KeySharingResponse(new[] { MASTER_KEY, SITE_KEY }, identityScope));
            Assert.True(refreshResult.Success);

            var advertisingToken = AdvertisingTokenBuilder.Builder().WithVersion(tokenVersion).WithScope(identityScope).WithGenerated(DateTime.UtcNow.AddMinutes(31)).Build();

            var res = client.Decrypt(advertisingToken);
            BidstreamClientTests.AssertSuccess(res, tokenVersion);
        }

        [Theory]
        [InlineData(IdentityScope.UID2, TokenVersion.V2)]
        [InlineData(IdentityScope.EUID, TokenVersion.V2)]
        [InlineData(IdentityScope.UID2, TokenVersion.V3)]
        [InlineData(IdentityScope.EUID, TokenVersion.V3)]
        [InlineData(IdentityScope.UID2, TokenVersion.V4)]
        [InlineData(IdentityScope.EUID, TokenVersion.V4)]
        private void TokenLifetimeTooLongLegacyClient(IdentityScope identityScope, TokenVersion tokenVersion)
        {    //similar to BidstreamClientTests.TokenLifetimeTooLongLegacyClient, but uses KeySharingResponse and Decrypt without domain parameter
            UID2Client client = new("endpoint", "authkey", CLIENT_SECRET, identityScope);

            var refreshResult = client.RefreshJson(KeySharingResponse(new[] { MASTER_KEY, SITE_KEY }, identityScope));
            Assert.True(refreshResult.Success);

            var advertisingToken = AdvertisingTokenBuilder.Builder().WithVersion(tokenVersion).WithScope(identityScope).WithExpiry(DateTime.UtcNow.AddDays(3).AddMinutes(1)).Build();

            var res = client.Decrypt(advertisingToken);
            BidstreamClientTests.AssertSuccess(res, tokenVersion);
        }



    }
}
