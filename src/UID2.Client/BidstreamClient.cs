using System;


namespace UID2.Client
{
    public class BidstreamClient
    {
        private readonly TokenHelper _tokenHelper;

        public BidstreamClient(string endpoint, string authKey, string secretKey)
        {
            _tokenHelper = new TokenHelper(endpoint, authKey, secretKey);
        }

        public DecryptionResponse DecryptTokenIntoRawUid(string token, string domainOrAppNameFromBidRequest)
        {
            return DecryptTokenIntoRawUid(token, domainOrAppNameFromBidRequest, DateTime.UtcNow);
        }

        internal DecryptionResponse DecryptTokenIntoRawUid(string token, string domainOrAppNameFromBidRequest, DateTime utcNow)
        {
            return _tokenHelper.Decrypt(token, utcNow, domainOrAppNameFromBidRequest, ClientType.Bidstream);
        }


        public RefreshResponse Refresh()
        {
            return _tokenHelper.Refresh("/v2/key/bidstream");
        }

        internal RefreshResponse RefreshJson(string json)
        {
            return _tokenHelper.RefreshJson(json);
        }

    }
}
