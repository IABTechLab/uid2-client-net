using System;
using UID2.Client;
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
        
        public class BuilderSetterTests
        {
            private readonly Key _someKey = new(75, 10, DateTime.Now.AddSeconds(42), DateTime.Now.AddHours(42), DateTime.Now.AddDays(42), MASTER_SECRET);
            
            [Fact]
            public void Version()
            {
                var builder = Builder().WithVersion(TokenVersion.V3);
                Assert.Equal(TokenVersion.V3, builder.Version);
            }
            
            [Fact]
            public void RawUid()
            {
                var rawUid = "raw uid";
                var builder = Builder().WithRawUid(rawUid);
                Assert.Equal(rawUid, builder.RawUid);
            }
            
            [Fact]
            public void MasterKey()
            {
                var builder = Builder().WithMasterKey(_someKey);
                Assert.Equal(_someKey, builder.MasterKey);
            }
            
            [Fact]
            public void SiteKey()
            {
                var builder = Builder().WithSiteKey(_someKey);
                Assert.Equal(_someKey, builder.SiteKey);
            }
            
            [Fact]
            public void SiteId()
            {
                // There is no setter, default only
                var builder = Builder();
                Assert.Equal(SITE_ID, builder.SiteId);
            }
            
            [Fact]
            public void PrivacyBits()
            {
                var privacyBits = 42;
                var builder = Builder().WithPrivacyBits(privacyBits);
                Assert.Equal(privacyBits, builder.PrivacyBits);
            }
            
            [Fact]
            public void Expiry()
            {
                var expiry = DateTime.Now.AddHours(42);
                var builder = Builder().WithExpiry(expiry);
                Assert.Equal(expiry, builder.Expiry);
            }
            
            [Fact]
            public void Scope()
            {
                // There is no setter, default only
                var builder = Builder();
                Assert.Equal(IdentityScope.UID2, builder.Scope);
            }
        }
    }
}