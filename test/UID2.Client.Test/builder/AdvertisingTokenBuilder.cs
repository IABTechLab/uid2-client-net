using System;
using UID2.Client;
using UID2.Client.Utils;
using static uid2_client.test.TestData;

namespace uid2_client.test.builder
{
    internal class AdvertisingTokenBuilder
    {
        private TokenVersion _tokenVersion = TokenVersion.V4;
        private string _rawUid = EXAMPLE_UID;
        private Key _masterKey = MASTER_KEY;
        private Key _siteKey = SITE_KEY;
        private int _siteId = SITE_ID;
        private int _privacyBits = PrivacyBitsBuilder.Builder().WithAllFlagsDisabled().Build();
        private DateTime _expiry = DateTime.UtcNow.AddHours(1);
        private IdentityScope _identityScope = IdentityScope.UID2;

        internal static AdvertisingTokenBuilder Builder()
        {
            return new AdvertisingTokenBuilder();
        }

        internal AdvertisingTokenBuilder WithVersion(TokenVersion version)
        {
            _tokenVersion = version;
            return this;
        }

        internal AdvertisingTokenBuilder WithRawUid(string rawUid)
        {
            _rawUid = rawUid;
            return this;
        }

        internal AdvertisingTokenBuilder WithMasterKey(Key masterKey)
        {
            _masterKey = masterKey;
            return this;
        }

        internal AdvertisingTokenBuilder WithSiteKey(Key siteKey)
        {
            _siteKey = siteKey;
            return this;
        }

        internal AdvertisingTokenBuilder WithSiteId(int siteId)
        {
            _siteId = siteId;
            return this;
        }

        internal AdvertisingTokenBuilder WithPrivacyBits(int privacyBits)
        {
            _privacyBits = privacyBits;
            return this;
        }

        internal AdvertisingTokenBuilder withExpiry(DateTime expiry)
        {
            _expiry = expiry;
            return this;
        }

        internal AdvertisingTokenBuilder WithIdentityScope(IdentityScope identityScope)
        {
            _identityScope = identityScope;
            return this;
        }

        internal string Build()
        {
            var encryptParams = new UID2TokenGenerator.Params().WithPrivacyBits(_privacyBits).WithTokenExpiry(_expiry);
            encryptParams.IdentityScope = (int) _identityScope;
            return _tokenVersion switch
            {
                TokenVersion.V2 => UID2TokenGenerator.GenerateUid2TokenV2(_rawUid, _masterKey, _siteId, _siteKey, encryptParams),
                TokenVersion.V3 => UID2TokenGenerator.GenerateUid2TokenV3(_rawUid, _masterKey, _siteId, _siteKey, encryptParams),
                TokenVersion.V4 => UID2TokenGenerator.GenerateUid2TokenV4(_rawUid, _masterKey, _siteId, _siteKey, encryptParams),
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