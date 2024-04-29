using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json.Linq;
using UID2.Client.Utils;

namespace UID2.Client.Test
{
    internal static class TestData
    {
        internal const long MASTER_KEY_ID = 164;
        internal const long SITE_KEY_ID = 165;
        internal const int SITE_ID = 9000;
        internal const int SITE_ID2 = 2;

        internal static readonly byte[] MASTER_SECRET =
        {
            139, 37, 241, 173, 18, 92, 36, 232, 165, 168, 23, 18, 38, 195, 123, 92, 160, 136, 185, 40, 91, 173, 165,
            221, 168, 16, 169, 164, 38, 139, 8, 155
        };

        internal static readonly byte[] SITE_SECRET =
        {
            32, 251, 7, 194, 132, 154, 250, 86, 202, 116, 104, 29, 131, 192, 139, 215, 48, 164, 11, 65, 226, 110, 167,
            14, 108, 51, 254, 125, 65, 24, 23, 133
        };

        internal static readonly DateTime NOW = DateTime.UtcNow;
        internal static readonly DateTime YESTERDAY = NOW.AddDays(-1);
        internal static readonly DateTime IN_2_DAYS = NOW.AddDays(2);
        internal static readonly DateTime TOMORROW = NOW.AddDays(1);

        internal static readonly Key MASTER_KEY =
            new(MASTER_KEY_ID, -1, YESTERDAY, NOW, TOMORROW, MASTER_SECRET);

        internal static readonly Key SITE_KEY = new(SITE_KEY_ID, SITE_ID, NOW.AddDays(-10), YESTERDAY, TOMORROW,
            SITE_SECRET);

        internal const string EXAMPLE_EMAIL_RAW_UID2_V2 = "ywsvDNINiZOVSsfkHpLpSJzXzhr6Jx9Z/4Q0+lsEUvM=";
        internal const string EXAMPLE_PHONE_RAW_UID2_V3 = "BFOsW2SkK0egqbfyiALtpti5G/cG+PcEvjkoHl56rEV8";
        internal static readonly string CLIENT_SECRET = "ioG3wKxAokmp+rERx6A4kM/13qhyolUXIu14WN16Spo=";
        internal static readonly byte[] SOME_DATA = { 1, 2, 3, 4, 5, 6 };

        internal static readonly byte[] TEST_SECRET = MakeTestSecret(9);

        internal static string KeySetToJson(params Key[] keys)
        {
            return @"{""body"": [" + string.Join(",", keys.Select(k => $@"{{""id"": {k.Id},
                ""site_id"": {k.SiteId},
                ""created"": {DateTimeUtils.DateTimeToEpochSeconds(k.Created)},
                ""activates"": {DateTimeUtils.DateTimeToEpochSeconds(k.Activates)},
                ""expires"": {DateTimeUtils.DateTimeToEpochSeconds(k.Expires)},
                ""secret"": ""{Convert.ToBase64String(k.Secret)}""
                }}")) + "]}";
        }

        internal static string KeySharingResponse(IEnumerable<Key> keys, int? callerSiteId = SITE_ID, int? defaultKeysetId = null, int? tokenExpirySeconds = null)
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
                    keys = keys.Select(keyToJson).ToArray(),
                    site_data = new[]
                    {
                        new
                        {
                            id = SITE_ID,
                            domain_names = new[] { "example.com", "example.org", "com.123.Game.App.android" }
                        },
                        new
                        {
                            id = SITE_ID2,
                            domain_names = new[] { "example.net", "example.edu", "com.123.Game.App.ios" }
                        }
                    }
                }
            });

            if (defaultKeysetId != null)
            {
                json["body"]["default_keyset_id"] = defaultKeysetId;
            }

            return json.ToString();
        }

        private static byte[] MakeTestSecret(byte value)
        {
            var ret = new byte[32];
            Array.Fill(ret, value);
            return ret;
        }
    }
}