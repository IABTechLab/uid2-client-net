using System;
using UID2.Client;
using UID2.Client.Utils;
using Xunit;
using static uid2_client.test.builder.AdvertisingTokenBuilder;
using static uid2_client.test.TestData;

namespace uid2_client.test.builder
{
    public class AdvertisingTokenBuilderTest
    {
        public class CreatesTokenOfDesiredVersion
        {
            private const int V2TokenLength = 180;
            private const int V3TokenLength = 220;
            private const int V4TokenLength = 218;

            [Fact]
            public void V2()
            {
                var token = Builder().WithVersion(TokenVersion.V2).Build();
                Assert.Equal(V2TokenLength, token.Length);
            }

            [Fact]
            public void V3()
            {
                var token = Builder().WithVersion(TokenVersion.V3).Build();
                Assert.Equal(V3TokenLength, token.Length);
            }

            [Fact]
            public void V4()
            {
                var token = Builder().WithVersion(TokenVersion.V4).Build();
                Assert.Equal(V4TokenLength, token.Length);
            }

            [Fact]
            public void ByDefaultCreatesV4Token()
            {
                var token = Builder().Build();
                Assert.Equal(V4TokenLength, token.Length);
            }
        }
        
        [Fact]
        public void CreatesTokens()
        {
            var privacyBits = 20;
            var expiry = DateTime.Today;
            var masterKey = new Key(MASTER_KEY_ID, -1, DateTime.Now, DateTime.Now, DateTime.Now, MASTER_SECRET);
            var siteKey = new Key(MASTER_KEY_ID, -1, DateTime.Now, DateTime.Now.AddDays(1), DateTime.Now, MASTER_SECRET);
            var rawUid = "dGVzdCB1aWQ=";
            var expectedToken = "expected token";

            string actualRawUid = null;
            Key actualMasterKey = null;
            Key actualSiteKey = null;
            int actualSideId = -100;
            UID2TokenGenerator.Params actualParams = null;

            string FakeV4Generate(string rawUid, Key masterKey, int sideId, Key siteKey, UID2TokenGenerator.Params encryptParams)
            {
                actualRawUid = rawUid;
                actualMasterKey = masterKey;
                actualSideId = sideId;
                actualSiteKey = siteKey;
                actualParams = encryptParams;
                return expectedToken;
            }

            var token = new AdvertisingTokenBuilder(null, null, FakeV4Generate)
                .WithPrivacyBits(privacyBits)
                .WithVersion(TokenVersion.V4)
                .WithExpiry(expiry)
                .WithMasterKey(masterKey)
                .WithRawUid(rawUid)
                .WithSiteKey(siteKey)
                .Build();
            
            Assert.Equal(expectedToken, token);
            Assert.Equal(rawUid, actualRawUid);
            Assert.Equal(masterKey, actualMasterKey);
            Assert.Equal(SITE_ID, actualSideId);  // Default, never overridden
            Assert.Equal(siteKey, actualSiteKey);

            Assert.NotNull(actualParams);
            Assert.Equal(privacyBits, actualParams.PrivacyBits);
            Assert.Equal(expiry, actualParams.TokenExpiry);
            Assert.Equal((int) IdentityScope.UID2, actualParams.IdentityScope); // Default, never overridden
        }
    }
}