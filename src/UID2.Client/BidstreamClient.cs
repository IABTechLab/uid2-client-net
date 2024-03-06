using System;


namespace UID2.Client
{
    public class BidstreamClient
    {
        private TokenHelper _tokenHelper;

        public BidstreamClient(string endpoint, string authKey, string secretKey)
        {
            _tokenHelper = new TokenHelper(endpoint, authKey, secretKey);
        }

        public DecryptionResponse DecryptTokenIntoRawUid(string token, string domainNameFromBidRequest)
        {
            return _tokenHelper.Decrypt(token, DateTime.UtcNow, domainNameFromBidRequest, ClientType.Bidstream);
        }

        public RefreshResponse Refresh()
        {
            return _tokenHelper.Refresh();
        }

        internal RefreshResponse RefreshJson(string json)
        {
            return _tokenHelper.RefreshJson(json);
        }

    }
}
