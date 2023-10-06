using System;
using System.IO;
using System.Linq;
using UID2.Client.Utils;
using Xunit;

namespace UID2.Client.Test
{
    public class EncryptionTestsV4
    {
        const long MASTER_KEY_ID = 164;
        const long SITE_KEY_ID = 165;
        const int SITE_ID = 9000; //const required for switch expression
        const int SITE_ID2 = 2;
        const string EXAMPLE_EMAIL_UID = "ywsvDNINiZOVSsfkHpLpSJzXzhr6Jx9Z/4Q0+lsEUvM=";
        const string EXAMPLE_PHONE_UID = "BFOsW2SkK0egqbfyiALtpti5G/cG+PcEvjkoHl56rEV8";
        private static readonly byte[] MASTER_SECRET = { 139, 37, 241, 173, 18, 92, 36, 232, 165, 168, 23, 18, 38, 195, 123, 92, 160, 136, 185, 40, 91, 173, 165, 221, 168, 16, 169, 164, 38, 139, 8, 155 };
        private static readonly byte[] SITE_SECRET = { 32, 251, 7, 194, 132, 154, 250, 86, 202, 116, 104, 29, 131, 192, 139, 215, 48, 164, 11, 65, 226, 110, 167, 14, 108, 51, 254, 125, 65, 24, 23, 133 };
        private static readonly DateTime NOW = DateTime.UtcNow;
        private static readonly Key MASTER_KEY = new Key(MASTER_KEY_ID, -1, NOW.AddDays(-1), NOW, NOW.AddDays(1), MASTER_SECRET);
        private static readonly Key SITE_KEY = new Key(SITE_KEY_ID, SITE_ID, NOW.AddDays(-10), NOW.AddDays(-1), NOW.AddDays(1), SITE_SECRET);
        private static readonly string CLIENT_SECRET = "ioG3wKxAokmp+rERx6A4kM/13qhyolUXIu14WN16Spo=";

        // unit tests to ensure the base64url encoding and decoding are identical in all supported
        // uid2 client sdks in different programming languages
        [Fact]
        public void crossPlatformConsistencyCheck_Base64UrlTestCases()
        {
            byte[] case1 = { 0xff, 0xE0, 0x88, 0xFF, 0xEE, 0x99, 0x99 };
            //the Base64 equivalent is "/+CI/+6ZmQ=="
            //and we want the Base64URL encoded to remove 2 '=' paddings at the back
            crossPlatformConsistencyCheck_Base64UrlTest(case1, "_-CI_-6ZmQ");

            //the Base64 equivalent is "/+CI/+6ZmZk=" to remove 1 padding
            byte[] case2 = { 0xff, 0xE0, 0x88, 0xFF, 0xEE, 0x99, 0x99, 0x99 };
            crossPlatformConsistencyCheck_Base64UrlTest(case2, "_-CI_-6ZmZk");

            //the Base64 equivalent is "/+CI/+6Z" which requires no padding removal
            byte[] case3 = { 0xff, 0xE0, 0x88, 0xFF, 0xEE, 0x99 };
            crossPlatformConsistencyCheck_Base64UrlTest(case3, "_-CI_-6Z");

        }

        public void crossPlatformConsistencyCheck_Base64UrlTest(byte[] rawInput, string expectedBase64URLStr)
        {
            var stream = new MemoryStream();
            var writer = new BigEndianByteWriter(stream);
            for (int i = 0; i < rawInput.Length; i++)
            {
                writer.Write(rawInput[i]);
            }

            string base64UrlEncodedStr = UID2Base64UrlCoder.Encode(stream.ToArray());
            //string base64UrlEncodedStr = Convert.ToBase64String(stream.ToArray());
            Assert.Equal(expectedBase64URLStr, base64UrlEncodedStr);

            byte[] decoded = UID2Base64UrlCoder.Decode(base64UrlEncodedStr);
            Assert.Equal(rawInput.Length, decoded.Length);
            for (int i = 0; i < decoded.Length; i++)
            {
                Assert.Equal(rawInput[i], decoded[i]);
            }
        }

        // verify that the Base64URL decoder can decode Base64URL string with NO '=' paddings added 
        [Fact]
        public void crossPlatformConsistencyCheck_Decrypt()
        {
            string crossPlatformAdvertisingToken =
                "AIAAAACkOqJj9VoxXJNnuX3v-ymceRf8_Av0vA5asOj9YBZJc1kV1vHdmb0AIjlzWnFF-gxIlgXqhRFhPo3iXpugPBl3gv4GKnGkw-Zgm2QqMsDPPLpMCYiWrIUqHPm8hQiq9PuTU-Ba9xecRsSIAN0WCwKLwA_EDVdzmnLJu64dQoeYmuu3u1G2EuTkuMrevmP98tJqSUePKwnfK73-0Zdshw";
            //Sunday, 1 January 2023 1:01:01 AM UTC
            var referenceTimestampMs = 1672534861000L;
            // 1 hour before ref timestamp
            var establishedMs = referenceTimestampMs - (3600 * 1000);
            var lastRefreshedMs = referenceTimestampMs;
            var tokenCreatedMs = referenceTimestampMs;
            var masterKeyCreated = DateTimeOffset.FromUnixTimeMilliseconds(referenceTimestampMs).DateTime.AddDays(-1);
            var siteKeyCreated = DateTimeOffset.FromUnixTimeMilliseconds(referenceTimestampMs).DateTime.AddDays(-10);
            var masterKeyActivates = DateTimeOffset.FromUnixTimeMilliseconds(referenceTimestampMs).DateTime;
            var siteKeyActivates = DateTimeOffset.FromUnixTimeMilliseconds(referenceTimestampMs).DateTime.AddDays(-1);
            //for the foreseeable future...
            var masterKeyExpires = DateTimeOffset.FromUnixTimeMilliseconds(referenceTimestampMs).DateTime
                .AddDays(1 * 365 * 20);
            var siteKeyExpires = DateTimeOffset.FromUnixTimeMilliseconds(referenceTimestampMs).DateTime
                .AddDays(1 * 365 * 20);
            var encryptParams = UID2TokenGenerator.DefaultParams.WithTokenExpiry(DateTimeOffset
                .FromUnixTimeMilliseconds(referenceTimestampMs).DateTime.AddDays(1 * 365 * 20));

            Key masterKey = new Key(MASTER_KEY_ID, -1, masterKeyCreated, masterKeyActivates, masterKeyExpires,
                MASTER_SECRET);
            Key siteKey = new Key(SITE_KEY_ID, SITE_ID, siteKeyCreated, siteKeyActivates, siteKeyExpires, SITE_SECRET);

            UID2Client client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));

            //verify that the dynamically created ad token can be decrypted
            string runtimeAdvertisingToken =
                GenerateUid2TokenV4(EXAMPLE_EMAIL_UID, masterKey, SITE_ID, siteKey, encryptParams);
            //best effort check as the token might simply just not require padding 
            Assert.Equal(-1, runtimeAdvertisingToken.IndexOf('='));

            Assert.Equal(-1, runtimeAdvertisingToken.IndexOf('+'));
            Assert.Equal(-1, runtimeAdvertisingToken.IndexOf('/'));

            var res = client.Decrypt(crossPlatformAdvertisingToken, NOW);
            Assert.Equal(EXAMPLE_EMAIL_UID, res.Uid);
            //can also decrypt a known token generated from other SDK
            res = client.Decrypt(crossPlatformAdvertisingToken, NOW);
            Assert.Equal(EXAMPLE_EMAIL_UID, res.Uid);
        }
        
        private static void ValidateAdvertisingToken(string advertisingTokenString, IdentityScope identityScope, IdentityType identityType) {
            string firstChar = advertisingTokenString.Substring(0, 1);
            if (identityScope == IdentityScope.UID2)
                Assert.Equal(identityType == IdentityType.Email ? "A" : "B", firstChar);
            else
                Assert.Equal(identityType == IdentityType.Email ? "E" : "F", firstChar);

            string secondChar = advertisingTokenString.Substring(1, 1);
            Assert.Equal("4", secondChar);

            //No URL-unfriendly characters allowed:
            Assert.Equal(-1, advertisingTokenString.IndexOf('='));
            Assert.Equal(-1, advertisingTokenString.IndexOf('+'));
            Assert.Equal(-1, advertisingTokenString.IndexOf('/'));
        }

        private static string GenerateUid2TokenV4(string uid, Key masterKey, int siteId, Key siteKey, UID2TokenGenerator.Params tokenGeneratorParams)
        {
            string advertisingToken = UID2TokenGenerator.GenerateUid2TokenV4(uid, masterKey, siteId, siteKey, tokenGeneratorParams);
            ValidateAdvertisingToken(advertisingToken, IdentityScope.UID2, IdentityType.Email);
            return advertisingToken;
        }

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
                ? UID2TokenGenerator.GenerateUid2TokenV4(uid, MASTER_KEY, SITE_ID, SITE_KEY, UID2TokenGenerator.DefaultParams)
                : UID2TokenGenerator.GenerateEuidTokenV4(uid, MASTER_KEY, SITE_ID, SITE_KEY, UID2TokenGenerator.DefaultParams);
            var res = client.Decrypt(advertisingToken, NOW);
            Assert.True(res.Success);
            Assert.Equal(uid, res.Uid);
            Assert.Equal(identityType, res.IdentityType);
            Assert.Equal(4, res.AdvertisingTokenVersion);
        }

        [Fact]
        public void SmokeTest()
        {
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            var refreshResult = client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            Assert.True(refreshResult.Success);
            
            string advertisingToken = GenerateUid2TokenV4(EXAMPLE_EMAIL_UID, MASTER_KEY, SITE_ID, SITE_KEY, UID2TokenGenerator.DefaultParams);
            var res = client.Decrypt(advertisingToken, NOW);
            Assert.True(res.Success);
            Assert.Equal(EXAMPLE_EMAIL_UID, res.Uid);
            Assert.Equal(IdentityType.Email, res.IdentityType);
            Assert.Equal(4, res.AdvertisingTokenVersion);
        }

        [Fact]
        public void EmptyKeyContainer()
        {
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            var advertisingToken = GenerateUid2TokenV4(EXAMPLE_EMAIL_UID, MASTER_KEY, SITE_ID, SITE_KEY, UID2TokenGenerator.DefaultParams);
            var res = client.Decrypt(advertisingToken, NOW);
            Assert.False(res.Success);
            Assert.Equal(DecryptionStatus.NotInitialized, res.Status);
        }

        [Fact]
        public void ExpiredKeyContainer()
        {
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            var advertisingToken = GenerateUid2TokenV4(EXAMPLE_EMAIL_UID, MASTER_KEY, SITE_ID, SITE_KEY, UID2TokenGenerator.DefaultParams);

            Key masterKeyExpired = new Key(MASTER_KEY_ID, -1, NOW, NOW.AddHours(-2), NOW.AddHours(-1), MASTER_SECRET);
            Key siteKeyExpired = new Key(SITE_KEY_ID, SITE_ID, NOW, NOW.AddHours(-2), NOW.AddHours(-1), SITE_SECRET);
            client.RefreshJson(KeySetToJson(masterKeyExpired, siteKeyExpired));

            var res = client.Decrypt(advertisingToken, NOW);
            Assert.False(res.Success);
            Assert.Equal(DecryptionStatus.KeysNotSynced, res.Status);
        }

        [Fact]
        public void NotAuthorizedForMasterKey()
        {
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            var advertisingToken = GenerateUid2TokenV4(EXAMPLE_EMAIL_UID, MASTER_KEY, SITE_ID, SITE_KEY, UID2TokenGenerator.DefaultParams);

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
            byte[] payload = UID2Base64UrlCoder.Decode(GenerateUid2TokenV4(EXAMPLE_EMAIL_UID, MASTER_KEY, SITE_ID, SITE_KEY, UID2TokenGenerator.DefaultParams));
            var advertisingToken = UID2Base64UrlCoder.Encode(payload.SkipLast(1).ToArray());

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
            var advertisingToken = GenerateUid2TokenV4(EXAMPLE_EMAIL_UID, MASTER_KEY, SITE_ID, SITE_KEY, encryptParams);

            var res = client.Decrypt(advertisingToken, expiry.AddSeconds(1));
            Assert.Equal(DecryptionStatus.ExpiredToken, res.Status);

            res = client.Decrypt(advertisingToken, expiry.AddSeconds(-1));
            Assert.Equal(EXAMPLE_EMAIL_UID, res.Uid);
        }

        [Fact]
        public void EncryptDataSiteIdFromToken()
        {
            byte[] data = { 1, 2, 3, 4, 5, 6 };
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            string advertisingToken = GenerateUid2TokenV4(EXAMPLE_EMAIL_UID, MASTER_KEY, SITE_ID, SITE_KEY, UID2TokenGenerator.DefaultParams);
            var encrypted = client.EncryptData(EncryptionDataRequest.ForData(data).WithAdvertisingToken(advertisingToken));
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            var decrypted = client.DecryptData(encrypted.EncryptedData);
            Assert.Equal(DecryptionStatus.Success, decrypted.Status);
            Assert.Equal(data, decrypted.DecryptedData);
        }

        [Fact]
        public void EncryptDataSiteIdFromTokenCustomSiteKeySiteId()
        {
            byte[] data = { 1, 2, 3, 4, 5, 6 };
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            string advertisingToken = GenerateUid2TokenV4(EXAMPLE_EMAIL_UID, MASTER_KEY, SITE_ID2, SITE_KEY, UID2TokenGenerator.DefaultParams);
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
            var advertisingToken = GenerateUid2TokenV4(EXAMPLE_EMAIL_UID, MASTER_KEY, SITE_ID, SITE_KEY, UID2TokenGenerator.DefaultParams);
            Assert.Throws<ArgumentException>(() =>
                client.EncryptData(EncryptionDataRequest.ForData(data).WithAdvertisingToken(advertisingToken).WithSiteId(SITE_KEY.SiteId)));
        }

        [Fact]
        public void EncryptDataTokenDecryptKeyExpired()
        {
            byte[] data = { 1, 2, 3, 4, 5, 6 };
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            Key key = new Key(SITE_KEY_ID, SITE_ID2, NOW, NOW, NOW.AddDays(-1), MakeTestSecret(9));
            client.RefreshJson(KeySetToJson(MASTER_KEY, key));
            string advertisingToken = GenerateUid2TokenV4(EXAMPLE_EMAIL_UID, MASTER_KEY, SITE_ID, key, UID2TokenGenerator.DefaultParams);
            var encrypted = client.EncryptData(EncryptionDataRequest.ForData(data).WithAdvertisingToken(advertisingToken));
            Assert.Equal(EncryptionStatus.NotAuthorizedForKey, encrypted.Status);
        }

        [Fact]
        public void EncryptDataTokenExpired()
        {
            var expiry = NOW.AddSeconds(-60);
            var encryptParams = UID2TokenGenerator.DefaultParams.WithTokenExpiry(expiry);

            byte[] data = { 1, 2, 3, 4, 5, 6 };
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            client.RefreshJson(KeySetToJson(MASTER_KEY, SITE_KEY));
            var advertisingToken = GenerateUid2TokenV4(EXAMPLE_EMAIL_UID, MASTER_KEY, SITE_ID, SITE_KEY, encryptParams);
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

        //////////////////////  Sharing tests
        ///
        private UID2Client SharingSetupAndEncrypt(out string advertisingToken)
        {
            var client = new UID2Client("endpoint", "authkey", CLIENT_SECRET, IdentityScope.UID2);
            var json = KeySetToJsonForSharing(MASTER_KEY, SITE_KEY);
            var refreshResult = client.RefreshJson(json);
            Assert.True(refreshResult.Success);

            advertisingToken = SharingEncrypt(client);

            return client;
        }

        private string SharingEncrypt(UID2Client client)
        {
            var encrypted = client.Encrypt(EXAMPLE_EMAIL_UID);
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            return encrypted.EncryptedData;
        }

        [Fact]
        public void CanEncryptAndDecryptForSharing()
        {
            var client = SharingSetupAndEncrypt(out string advertisingToken);

            var res = client.Decrypt(advertisingToken);
            Assert.True(res.Success);
            Assert.Equal(EXAMPLE_EMAIL_UID, res.Uid);
        }

        [Fact]
        public void CanDecryptAnotherClientsEncryptedToken()
        {
            var sendingClient = SharingSetupAndEncrypt(out string advertisingToken);

            var receivingClient = new UID2Client("endpoint2", "authkey2", "random secret", IdentityScope.UID2);
            var json = KeySetToJsonForSharingWithHeader(@"""default_keyset_id"": 12345,", callerSiteId: 4874, MASTER_KEY, SITE_KEY);

            var refreshResult = receivingClient.RefreshJson(json);
            Assert.True(refreshResult.Success);

            var res = receivingClient.Decrypt(advertisingToken);
            Assert.True(res.Success);
            Assert.Equal(EXAMPLE_EMAIL_UID, res.Uid);
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
        public void EuidClientProducesEuidToken()
        {
            var client = new UID2Client("endpoint", "authkey", CLIENT_SECRET, IdentityScope.EUID);
            var json = KeySetToJsonForSharing(MASTER_KEY, SITE_KEY);
            var refreshResult = client.RefreshJson(json);
            Assert.True(refreshResult.Success);

            string advertisingToken = SharingEncrypt(client);

            Assert.Equal("E", advertisingToken.Substring(0, 1));
        }

        [Fact]
        public void RawUidProducesCorrectIdentityTypeInToken()
        {
            var client = new UID2Client("endpoint", "authkey", CLIENT_SECRET, IdentityScope.UID2);
            var json = KeySetToJsonForSharing(MASTER_KEY, SITE_KEY);
            var refreshResult = client.RefreshJson(json);
            Assert.True(refreshResult.Success);

            //see UID2-79+Token+and+ID+format+v3 . Also note EUID does not support v2 or phone
            Assert.Equal(IdentityType.Email, GetTokenIdentityType("Q4bGug8t1xjsutKLCNjnb5fTlXSvIQukmahYDJeLBtk=", client)); //v2 +12345678901. Although this was generated from a phone number, it's a v2 raw UID which doesn't encode this information, so token assumes email by default.
            Assert.Equal(IdentityType.Phone, GetTokenIdentityType("BEOGxroPLdcY7LrSiwjY52+X05V0ryELpJmoWAyXiwbZ", client)); //v3 +12345678901
            Assert.Equal(IdentityType.Email, GetTokenIdentityType("oKg0ZY9ieD/CGMEjAA0kcq+8aUbLMBG0MgCT3kWUnJs=", client)); //v2 test@example.com
            Assert.Equal(IdentityType.Email, GetTokenIdentityType("AKCoNGWPYng/whjBIwANJHKvvGlGyzARtDIAk95FlJyb", client)); //v3 test@example.com
            Assert.Equal(IdentityType.Email, GetTokenIdentityType("EKCoNGWPYng/whjBIwANJHKvvGlGyzARtDIAk95FlJyb", client)); //v3 EUID test@example.com
        }

        private IdentityType GetTokenIdentityType(string rawUid, UID2Client client)
        {
            var encrypted = client.Encrypt(rawUid);
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);
            Assert.Equal(rawUid, client.Decrypt(encrypted.EncryptedData).Uid);

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
            Key MASTER_KEY2 = new Key(id: 264, siteId: -1, created: NOW.AddDays(-2), activates: NOW.AddDays(-1), expires: NOW.AddHours(-1), secret: MASTER_SECRET);
            Key SITE_KEY2 = new Key(id: 265, siteId: SITE_ID, created: NOW.AddDays(-10), activates: NOW.AddDays(-1), expires: NOW.AddHours(-1), secret: SITE_SECRET);

            var client = new UID2Client("endpoint", "authkey", CLIENT_SECRET, IdentityScope.UID2);
            var json = KeySetToJsonForSharing(MASTER_KEY, MASTER_KEY2, SITE_KEY, SITE_KEY2);
            var refreshResult = client.RefreshJson(json);
            Assert.True(refreshResult.Success);

            string advertisingToken = SharingEncrypt(client);

            var res = client.Decrypt(advertisingToken);
            Assert.True(res.Success);
            Assert.Equal(EXAMPLE_EMAIL_UID, res.Uid);
        }

        [Fact]
        public void CannotEncryptIfNoKeyFromTheDefaultKeyset()
        {
            var client = new UID2Client("endpoint", "authkey", CLIENT_SECRET, IdentityScope.UID2);
            var json = KeySetToJsonForSharing(MASTER_KEY);
            var refreshResult = client.RefreshJson(json);
            Assert.True(refreshResult.Success);

            var encrypted = client.Encrypt(EXAMPLE_EMAIL_UID);
            Assert.Equal(EncryptionStatus.NotAuthorizedForKey, encrypted.Status);
        }


        [Fact]
        public void CannotEncryptIfTheresNoDefaultKeysetHeader()
        {
            var client = new UID2Client("endpoint", "authkey", CLIENT_SECRET, IdentityScope.UID2);
            var json = KeySetToJsonForSharingWithHeader(defaultKeyset: "", SITE_ID, MASTER_KEY, SITE_KEY);
            var refreshResult = client.RefreshJson(json);
            Assert.True(refreshResult.Success);

            var encrypted = client.Encrypt(EXAMPLE_EMAIL_UID);
            Assert.Equal(EncryptionStatus.NotAuthorizedForKey, encrypted.Status);
        }

        [Fact]
        public void ExpiryInTokenMatchesExpiryInResponse()
        {
            var client = new UID2Client("endpoint", "authkey", CLIENT_SECRET, IdentityScope.UID2);
            var json = KeySetToJsonForSharingWithHeader(@"""default_keyset_id"": 99999, ""token_expiry_seconds"": 2,", SITE_ID, MASTER_KEY, SITE_KEY);
            var refreshResult = client.RefreshJson(json);
            Assert.True(refreshResult.Success);

            var encryptedAt = DateTime.UtcNow;
            var encrypted = client.Encrypt(EXAMPLE_EMAIL_UID, encryptedAt);
            Assert.Equal(EncryptionStatus.Success, encrypted.Status);

            var res = client.Decrypt(encrypted.EncryptedData, encryptedAt.AddSeconds(1));
            Assert.True(res.Success);
            Assert.Equal(EXAMPLE_EMAIL_UID, res.Uid);

            var futureDecryption = client.Decrypt(encrypted.EncryptedData, DateTime.UtcNow.AddSeconds(3));
            Assert.Equal(DecryptionStatus.ExpiredToken, futureDecryption.Status);
        }

        [Fact]
        public void EncryptKeyExpired()
        {
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            Key key = new Key(SITE_KEY_ID, SITE_ID, NOW, NOW, NOW.AddDays(-1), MakeTestSecret(9));
            client.RefreshJson(KeySetToJsonForSharing(MASTER_KEY, key));
            var encrypted = client.Encrypt(EXAMPLE_EMAIL_UID);
            Assert.Equal(EncryptionStatus.NotAuthorizedForKey, encrypted.Status); //note: KeyInactive was the result for EncryptData, because EncryptData allowed you to pass an expired key. In the Sharing scenario, expired and inactive keys are ignored when encrypting.
        }

        [Fact]
        public void EncryptKeyInactive()
        {
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            Key key = new Key(SITE_KEY_ID, SITE_ID, NOW, NOW.AddDays(1), NOW.AddDays(2), MakeTestSecret(9));
            client.RefreshJson(KeySetToJsonForSharing(MASTER_KEY, key));
            var encrypted = client.Encrypt(EXAMPLE_EMAIL_UID);
            Assert.Equal(EncryptionStatus.NotAuthorizedForKey, encrypted.Status);
        }


        [Fact]
        public void EncryptSiteKeyExpired()
        {
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            Key key = new Key(SITE_KEY_ID, SITE_ID, NOW, NOW, NOW.AddDays(-1), MakeTestSecret(9));
            client.RefreshJson(KeySetToJsonForSharing(MASTER_KEY, key));
            var encrypted = client.Encrypt(EXAMPLE_EMAIL_UID);
            Assert.Equal(EncryptionStatus.NotAuthorizedForKey, encrypted.Status);
        }

        [Fact]
        public void EncryptSiteKeyInactive()
        {
            var client = new UID2Client("ep", "ak", CLIENT_SECRET, IdentityScope.UID2);
            Key key = new Key(SITE_KEY_ID, SITE_ID, NOW, NOW.AddDays(1), NOW.AddDays(2), MakeTestSecret(9));
            client.RefreshJson(KeySetToJsonForSharing(MASTER_KEY, key));
            var encrypted = client.Encrypt(EXAMPLE_EMAIL_UID);
            Assert.Equal(EncryptionStatus.NotAuthorizedForKey, encrypted.Status);
        }

        
        private static string KeySetToJsonForSharing(params Key[] keys)
        {
            return KeySetToJsonForSharingWithHeader(@"""default_keyset_id"": 99999,", SITE_ID, keys);
        }

        private static string KeySetToJsonForSharingWithHeader(string defaultKeyset, int callerSiteId, params Key[] keys)
        {
            return $@"{{
                ""body"": {{
                    ""caller_site_id"": {callerSiteId},
                    ""master_keyset_id"": 1,
                    {defaultKeyset}
                    ""keys"": [" + string.Join(",", keys.Select(k => $@"{{
                        ""id"": {k.Id},
                        ""keyset_id"": {k.SiteId switch { -1 => 1, SITE_ID => 99999, _ => k.SiteId }},
                        ""created"": {DateTimeUtils.DateTimeToEpochSeconds(k.Created)},
                        ""activates"": {DateTimeUtils.DateTimeToEpochSeconds(k.Activates)},
                        ""expires"": {DateTimeUtils.DateTimeToEpochSeconds(k.Expires)},
                        ""secret"": ""{Convert.ToBase64String(k.Secret)}"" }}")) +
                @"] }}";
        }
    }
}
