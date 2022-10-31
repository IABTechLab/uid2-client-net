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
    }
}
