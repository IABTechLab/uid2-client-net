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
                unexpected_key_field = "123", //ensure new fields can be handled by old SDK versions
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
                    keys = keys.Select(keyToJson).ToArray(),
                    unexpected_header_field = "123" //ensure new fields can be handled by old SDK versions
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
        private void TokenGeneratedInTheFutureToSimulateClockSkew(IdentityScope identityScope, TokenVersion tokenVersion)
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
        private void TokenGeneratedInTheFutureWithinAllowedClockSkew(IdentityScope identityScope, TokenVersion tokenVersion)
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

            var advertisingToken = AdvertisingTokenBuilder.Builder().WithVersion(tokenVersion).WithScope(identityScope).WithGenerated(DateTime.UtcNow.AddDays(99)).Build();

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

            var advertisingToken = AdvertisingTokenBuilder.Builder().WithVersion(tokenVersion).WithScope(identityScope).WithExpiry(DateTime.UtcNow.AddDays(99)).Build();

            var res = client.Decrypt(advertisingToken);
            BidstreamClientTests.AssertSuccess(res, tokenVersion);
        }


        // tests below taken from EncryptionTestsV4.cs under "//  Sharing tests" comment and modified to use SharingClient and the new JSON /key/sharing response
        private SharingClient SharingSetupAndEncrypt(out string advertisingToken)
        {
            var json = KeySetToJsonForSharing(new [] {MASTER_KEY, SITE_KEY});
            var refreshResult = _client.RefreshJson(json);
            Assert.True(refreshResult.Success);

            advertisingToken = SharingEncrypt(_client);

            return _client;
        }

        private string SharingEncrypt(SharingClient client, IdentityScope identityScope = IdentityScope.UID2)
        {
            var encrypted = client.EncryptRawUidIntoToken(EXAMPLE_EMAIL_RAW_UID2_V2);
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            EncryptionTestsV4.ValidateAdvertisingToken(encrypted.EncryptedData, identityScope, IdentityType.Email, TokenVersion.V4);
            return encrypted.EncryptedData;
        }

        [Theory]
        [InlineData(IdentityScope.UID2)]
        [InlineData(IdentityScope.EUID)]
        private void ClientProducesTokenWithCorrectPrefix(IdentityScope identityScope)
        {
            var client = new SharingClient("endpoint", "authkey", CLIENT_SECRET);
            var json = KeySetToJsonForSharing(new[] { MASTER_KEY, SITE_KEY }, identityScope);
            var refreshResult = client.RefreshJson(json);
            Assert.True(refreshResult.Success);

            string advertisingToken = SharingEncrypt(client, identityScope); //this validates token and asserts
        }


        [Fact]
        public void CanEncryptAndDecryptForSharing()
        {
            var client = SharingSetupAndEncrypt(out string advertisingToken);

            var res = _client.DecryptTokenIntoRawUid(advertisingToken);
            Assert.True(res.Success);
            Assert.Equal(EXAMPLE_EMAIL_RAW_UID2_V2, res.Uid);
        }

        [Fact]
        public void CanDecryptAnotherClientsEncryptedToken()
        {
            var sendingClient = SharingSetupAndEncrypt(out string advertisingToken);

            var receivingClient = new SharingClient("endpoint2", "authkey2", "random secret");
            var json = KeySharingResponse(new[] { MASTER_KEY, SITE_KEY }, IdentityScope.UID2, callerSiteId: 4874, defaultKeysetId: 12345);

            var refreshResult = receivingClient.RefreshJson(json);
            Assert.True(refreshResult.Success);

            var res = receivingClient.DecryptTokenIntoRawUid(advertisingToken);
            Assert.True(res.Success);
            Assert.Equal(EXAMPLE_EMAIL_RAW_UID2_V2, res.Uid);
        }

        [Fact]
        public void SharingTokenIsV4()
        {
            var client = SharingSetupAndEncrypt(out string advertisingToken);

            char[] base64SpecialChars = { '+', '/', '=' };
            Boolean containsBase64SpecialChars = advertisingToken.IndexOfAny(base64SpecialChars) != -1;
            Assert.False(containsBase64SpecialChars);
        }

        [Fact]
        public void Uid2ClientProducesUid2Token()
        {
            var client = SharingSetupAndEncrypt(out string advertisingToken);

            Assert.Equal("A", advertisingToken.Substring(0, 1));
        }


        [Fact]
        public void RawUidProducesCorrectIdentityTypeInToken()
        {
            var json = KeySetToJsonForSharing(new [] {MASTER_KEY, SITE_KEY});
            var refreshResult = _client.RefreshJson(json);
            Assert.True(refreshResult.Success);

            //see UID2-79+Token+and+ID+format+v3 . Also note EUID does not support v2 or phone
            Assert.Equal(IdentityType.Email, GetTokenIdentityType("Q4bGug8t1xjsutKLCNjnb5fTlXSvIQukmahYDJeLBtk=")); //v2 +12345678901. Although this was generated from a phone number, it's a v2 raw UID which doesn't encode this information, so token assumes email by default.
            Assert.Equal(IdentityType.Phone, GetTokenIdentityType("BEOGxroPLdcY7LrSiwjY52+X05V0ryELpJmoWAyXiwbZ")); //v3 +12345678901
            Assert.Equal(IdentityType.Email, GetTokenIdentityType("oKg0ZY9ieD/CGMEjAA0kcq+8aUbLMBG0MgCT3kWUnJs=")); //v2 test@example.com
            Assert.Equal(IdentityType.Email, GetTokenIdentityType("AKCoNGWPYng/whjBIwANJHKvvGlGyzARtDIAk95FlJyb")); //v3 test@example.com
            Assert.Equal(IdentityType.Email, GetTokenIdentityType("EKCoNGWPYng/whjBIwANJHKvvGlGyzARtDIAk95FlJyb")); //v3 EUID test@example.com
        }

        private IdentityType GetTokenIdentityType(string rawUid)
        {
            var encrypted = _client.EncryptRawUidIntoToken(rawUid);
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            Assert.Equal(rawUid, _client.DecryptTokenIntoRawUid(encrypted.EncryptedData).Uid);

            var firstChar = encrypted.EncryptedData.Substring(0, 1);
            if (firstChar == "A" || firstChar == "E") //from UID2-79+Token+and+ID+format+v3
                return IdentityType.Email;
            else if (firstChar == "F" || firstChar == "B")
                return IdentityType.Phone;

            throw new Exception("unknown IdentityType");
        }


        [Fact]
        public void MultipleKeysPerKeyset()
        {
            Key MASTER_KEY2 = new Key(id: 264, siteId: -1, created: NOW.AddDays(-2), activates: YESTERDAY, expires: NOW.AddHours(-1), secret: MASTER_SECRET);
            Key SITE_KEY2 = new Key(id: 265, siteId: SITE_ID, created: NOW.AddDays(-10), activates: YESTERDAY, expires: NOW.AddHours(-1), secret: SITE_SECRET);

            var json = KeySetToJsonForSharing(new [] {MASTER_KEY, MASTER_KEY2, SITE_KEY, SITE_KEY2});
            var refreshResult = _client.RefreshJson(json);
            Assert.True(refreshResult.Success);

            string advertisingToken = SharingEncrypt(_client);

            var res = _client.DecryptTokenIntoRawUid(advertisingToken);
            Assert.True(res.Success);
            Assert.Equal(EXAMPLE_EMAIL_RAW_UID2_V2, res.Uid);
        }

        [Fact]
        public void CannotEncryptIfNoKeyFromTheDefaultKeyset()
        {
            var json = KeySetToJsonForSharing(new[] {MASTER_KEY});
            var refreshResult = _client.RefreshJson(json);
            Assert.True(refreshResult.Success);

            var encrypted = _client.EncryptRawUidIntoToken(EXAMPLE_EMAIL_RAW_UID2_V2);
            Assert.Equal(EncryptionStatus.NotAuthorizedForKey, encrypted.Status);
        }


        [Fact]
        public void CannotEncryptIfTheresNoDefaultKeysetHeader()
        {
            var json = KeySharingResponse(new[] { MASTER_KEY, SITE_KEY }, IdentityScope.UID2,SITE_ID);
            var refreshResult = _client.RefreshJson(json);
            Assert.True(refreshResult.Success);

            var encrypted = _client.EncryptRawUidIntoToken(EXAMPLE_EMAIL_RAW_UID2_V2);
            Assert.Equal(EncryptionStatus.NotAuthorizedForKey, encrypted.Status);
        }

        [Fact]
        public void ExpiryInTokenMatchesExpiryInResponse()
        {
            var json = KeySharingResponse(new[] { MASTER_KEY, SITE_KEY }, IdentityScope.UID2,SITE_ID, defaultKeysetId: 99999, tokenExpirySeconds: 2);
            var refreshResult = _client.RefreshJson(json);
            Assert.True(refreshResult.Success);

            var encryptedAt = DateTime.UtcNow;
            var encrypted = _client.EncryptRawUidIntoToken(EXAMPLE_EMAIL_RAW_UID2_V2, encryptedAt);
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);

            var res = _client.DecryptTokenIntoRawUid(encrypted.EncryptedData, encryptedAt.AddSeconds(1));
            Assert.True(res.Success);
            Assert.Equal(EXAMPLE_EMAIL_RAW_UID2_V2, res.Uid);

            var futureDecryption = _client.DecryptTokenIntoRawUid(encrypted.EncryptedData, DateTime.UtcNow.AddSeconds(3));
            Assert.Equal(DecryptionStatus.ExpiredToken, futureDecryption.Status);
        }

        [Fact]
        public void EncryptKeyExpired()
        {
            Key key = new Key(SITE_KEY_ID, SITE_ID, NOW, NOW, YESTERDAY, TEST_SECRET);
            _client.RefreshJson(KeySetToJsonForSharing(new [] {MASTER_KEY, key}));
            var encrypted = _client.EncryptRawUidIntoToken(EXAMPLE_EMAIL_RAW_UID2_V2);
            Assert.Equal(EncryptionStatus.NotAuthorizedForKey,
                encrypted.Status); //note: KeyInactive was the result for EncryptData, because EncryptData allowed you to pass an expired key. In the Sharing scenario, expired and inactive keys are ignored when encrypting.
        }

        [Fact]
        public void EncryptKeyInactive()
        {
            Key key = new Key(SITE_KEY_ID, SITE_ID, NOW, TOMORROW, IN_2_DAYS, TEST_SECRET);
            _client.RefreshJson(KeySetToJsonForSharing(new [] {MASTER_KEY, key}));
            var encrypted = _client.EncryptRawUidIntoToken(EXAMPLE_EMAIL_RAW_UID2_V2);
            Assert.Equal(EncryptionStatus.NotAuthorizedForKey, encrypted.Status);
        }


        [Fact]
        public void EncryptSiteKeyExpired()
        {
            Key key = new Key(SITE_KEY_ID, SITE_ID, NOW, NOW, YESTERDAY, TEST_SECRET);
            _client.RefreshJson(KeySetToJsonForSharing(new [] {MASTER_KEY, key}));
            var encrypted = _client.EncryptRawUidIntoToken(EXAMPLE_EMAIL_RAW_UID2_V2);
            Assert.Equal(EncryptionStatus.NotAuthorizedForKey, encrypted.Status);
        }

        [Fact]
        public void EncryptSiteKeyInactive()
        {
            Key key = new Key(SITE_KEY_ID, SITE_ID, NOW, TOMORROW, IN_2_DAYS, TEST_SECRET);
            _client.RefreshJson(KeySetToJsonForSharing(new [] {MASTER_KEY, key}));
            var encrypted = _client.EncryptRawUidIntoToken(EXAMPLE_EMAIL_RAW_UID2_V2);
            Assert.Equal(EncryptionStatus.NotAuthorizedForKey, encrypted.Status);
        }


        private static string KeySetToJsonForSharing(IEnumerable<Key> keys, IdentityScope identityScope = IdentityScope.UID2)
        {
            return KeySharingResponse(keys, identityScope, SITE_ID, defaultKeysetId: 99999);
        }




    }
}
