using System;
using System.Collections.Generic;
using System.Linq;
using UID2.Client.Utils;
using Newtonsoft.Json.Linq;

namespace UID2.Client
{
    internal static class KeyParser
    {
        /// <summary>
        /// Parse json data and load keys
        /// </summary>
        internal static KeyContainer Parse(string json)
        {
            return Parse(JObject.Parse(json));
        }

        /// <summary>
        /// Parse json data and load keys
        /// </summary>
        internal static KeyContainer Parse(JObject json)
        {
            var bodyToken = json["body"];
            if (bodyToken.Type == JTokenType.Array)
            {   // key/latest response, which will become legacy
                var body = json.Value<JArray>("body");

                var keys = body.Select(i => (JObject)i).Select(item => new Key(
                        item.Value<long>("id"),
                        item.Value<int>("site_id"),
                        DateTimeUtils.FromEpochSeconds(item.Value<long>("created")),
                        DateTimeUtils.FromEpochSeconds(item.Value<long>("activates")),
                        DateTimeUtils.FromEpochSeconds(item.Value<long>("expires")),
                        Convert.FromBase64String(item.Value<string>("secret"))
                    )).ToList();

                return new KeyContainer(keys);
            }
            else
            {   // key/sharing response
                var body = json.Value<JObject>("body");
                var callerSiteId = body.Value<int>("caller_site_id");
                var masterKeysetId = body.Value<int>("master_keyset_id");
                var defaultKeysetId = body.Value<int>("default_keyset_id");
                var tokenExpirySeconds = body.Value<long>("token_expiry_seconds");
                if (tokenExpirySeconds == 0)
                {
                    const short defaultTokenExpiryDays = 30;
                    tokenExpirySeconds = defaultTokenExpiryDays * 24 * 60 * 60;
                }

                var keysJson = body.Value<JArray>("keys");

                var keys = keysJson.Select(i => (JObject)i).Select(item => Key.CreateKeysetKey(
                        item.Value<long>("id"),
                        item.Value<int>("keyset_id"),
                        DateTimeUtils.FromEpochSeconds(item.Value<long>("created")),
                        DateTimeUtils.FromEpochSeconds(item.Value<long>("activates")),
                        DateTimeUtils.FromEpochSeconds(item.Value<long>("expires")),
                        Convert.FromBase64String(item.Value<string>("secret"))
                    )).ToList();

                var sites = Enumerable.Empty<Site>();
                if (TryGetSitesJson(body, out var sitesJson))
                {
                    sites = sitesJson.Select(SiteFromJson).ToList();
                }

                return new KeyContainer(callerSiteId, masterKeysetId, defaultKeysetId, tokenExpirySeconds, keys, sites);
            }
        }

        private static bool TryGetSitesJson(JObject obj, out JArray value)
        {
            if (obj.TryGetValue("site_data", StringComparison.OrdinalIgnoreCase, out var sites) && sites.Type == JTokenType.Array)
            {
                value = (JArray)sites;
                return true;
            }

            value = default;
            return false;
        }

        private static Site SiteFromJson(JToken item)
        {
            var domainNames = (JArray)item["domain_names"];
            return new Site(item.Value<int>("id"), domainNames.Select(x => (string)x));
        }
    }
}
