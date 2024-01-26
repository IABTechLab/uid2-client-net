using System;
using UID2.Client;
using UID2.Client.Utils;
using static uid2_client.test.TestData;

namespace uid2_client.test.builder
{
    internal class AdvertisingTokenBuilder
    {
        public TokenVersion Version { get; private set; } = TokenVersion.V4;
        public string RawUid { get; private set; } = EXAMPLE_EMAIL_RAW_UID2_V2;
        public Key MasterKey { get; private set; } = MASTER_KEY;
        public Key SiteKey { get; private set; } = SITE_KEY;
        public int SiteId => SITE_ID;
        public int PrivacyBits { get; private set; } = PrivacyBitsBuilder.Builder().WithAllFlagsDisabled().Build();
        public DateTime Expiry { get; private set; } = DateTime.UtcNow.AddHours(1);
        public IdentityScope Scope { get; private set; } = IdentityScope.UID2;

        internal static AdvertisingTokenBuilder Builder()
        {
            return new AdvertisingTokenBuilder();
        }

        internal AdvertisingTokenBuilder WithVersion(TokenVersion version)
        {
            this.Version = version;
            return this;
        }

        internal AdvertisingTokenBuilder WithRawUid(string rawUid)
        {
            RawUid = rawUid;
            return this;
        }

        internal AdvertisingTokenBuilder WithMasterKey(Key masterKey)
        {
            MasterKey = masterKey;
            return this;
        }

        internal AdvertisingTokenBuilder WithSiteKey(Key siteKey)
        {
            SiteKey = siteKey;
            return this;
        }

        internal AdvertisingTokenBuilder WithPrivacyBits(int privacyBits)
        {
            PrivacyBits = privacyBits;
            return this;
        }

        internal AdvertisingTokenBuilder WithExpiry(DateTime expiry)
        {
            Expiry = expiry;
            return this;
        }

        internal AdvertisingTokenBuilder WithScope(IdentityScope scope)
        {
            Scope = scope;
            return this;
        }

        internal string Build()
        {
            var encryptParams = new UID2TokenGenerator.Params().WithPrivacyBits(PrivacyBits).WithTokenExpiry(Expiry);
            encryptParams.IdentityScope = (int) Scope;
            return Version switch
            {
                TokenVersion.V2 => UID2TokenGenerator.GenerateUid2TokenV2(RawUid, MasterKey, SiteId, SiteKey, encryptParams),
                TokenVersion.V3 => UID2TokenGenerator.GenerateUid2TokenV3(RawUid, MasterKey, SiteId, SiteKey, encryptParams),
                TokenVersion.V4 => UID2TokenGenerator.GenerateUid2TokenV4(RawUid, MasterKey, SiteId, SiteKey, encryptParams),
                _ => throw new ArgumentOutOfRangeException()
            };
        }

        internal enum TokenVersion
        {
            V2,
            V3,
            V4
        }
    }
}