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
        private readonly int _siteId = SITE_ID;
        private int _privacyBits = PrivacyBitsBuilder.Builder().WithAllFlagsDisabled().Build();
        private DateTime _expiry = DateTime.UtcNow.AddHours(1);
        private readonly IdentityScope _identityScope = IdentityScope.UID2;
        private Func<string, Key, int, Key, UID2TokenGenerator.Params, string> _generateUid2TokenV2;
        private Func<string, Key, int, Key, UID2TokenGenerator.Params, string> _generateUid2TokenV3;
        private Func<string, Key, int, Key, UID2TokenGenerator.Params, string> _generateUid2TokenV4;

        public AdvertisingTokenBuilder(
            Func<string, Key, int, Key, UID2TokenGenerator.Params, string> generateUid2TokenV2,
            Func<string, Key, int, Key, UID2TokenGenerator.Params, string> generateUid2TokenV3,
            Func<string, Key, int, Key, UID2TokenGenerator.Params, string> generateUid2TokenV4
        )
        {
            _generateUid2TokenV2 = generateUid2TokenV2;
            _generateUid2TokenV3 = generateUid2TokenV3;
            _generateUid2TokenV4 = generateUid2TokenV4;
        }

        internal static AdvertisingTokenBuilder Builder()
        {
            return new AdvertisingTokenBuilder(UID2TokenGenerator.GenerateUid2TokenV2, UID2TokenGenerator.GenerateUid2TokenV3, UID2TokenGenerator.GenerateUid2TokenV4);
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

        internal AdvertisingTokenBuilder WithPrivacyBits(int privacyBits)
        {
            _privacyBits = privacyBits;
            return this;
        }

        internal AdvertisingTokenBuilder WithExpiry(DateTime expiry)
        {
            _expiry = expiry;
            return this;
        }

        internal string Build()
        {
            var encryptParams = new UID2TokenGenerator.Params().WithPrivacyBits(_privacyBits).WithTokenExpiry(_expiry);
            encryptParams.IdentityScope = (int)_identityScope;
            return _tokenVersion switch
            {
                TokenVersion.V2 => _generateUid2TokenV2(_rawUid, _masterKey, _siteId, _siteKey, encryptParams),
                TokenVersion.V3 => _generateUid2TokenV3(_rawUid, _masterKey, _siteId, _siteKey, encryptParams),
                TokenVersion.V4 => _generateUid2TokenV4(_rawUid, _masterKey, _siteId, _siteKey, encryptParams),
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