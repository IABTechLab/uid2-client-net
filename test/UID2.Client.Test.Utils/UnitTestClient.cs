using System;
using System.Diagnostics;
using System.Linq;
using UID2.Client.Utils;

namespace UID2.Client.Test.Utils
{
    public class KeySetUtils
    {
        private const int SITE_ID = 9000;

        private static int CalculateKeySetId(int siteId)
        {
            //{k.SiteId switch { -1 => 1, SITE_ID => 99999, _ => k.SiteId }},
            switch (siteId)
            {
                case -1:
                    return 1;
                case SITE_ID:
                    return 99999;
                default:
                    return siteId;

            }
           
        }
        
        public static string KeySetToJsonForSharing(params Key[] keys)
        {
            return KeySetToJsonForSharingWithHeader(@"""default_keyset_id"": 99999,", SITE_ID, keys);
        }

        public static string KeySetToJsonForSharingWithHeader(string defaultKeyset, int callerSiteId, params Key[] keys)
        {
            return $@"{{
                ""body"": {{
                    ""caller_site_id"": {callerSiteId},
                    ""master_keyset_id"": 1,
                    {defaultKeyset}
                    ""keys"": [" + string.Join(",", keys.Select(k => $@"{{
                        ""id"": {k.Id},
                        ""keyset_id"": {CalculateKeySetId(k.SiteId)}, 
                        ""created"": {DateTimeUtils.DateTimeToEpochSeconds(k.Created)},
                        ""activates"": {DateTimeUtils.DateTimeToEpochSeconds(k.Activates)},
                        ""expires"": {DateTimeUtils.DateTimeToEpochSeconds(k.Expires)},
                        ""secret"": ""{Convert.ToBase64String(k.Secret)}"" }}")) +
                   @"] }}";
        }
    }
}