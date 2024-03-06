using System;

namespace UID2.Client
{
    public class SharingClient
    {
        private TokenHelper _tokenHelper;

        public SharingClient(string endpoint, string authKey, string secretKey)
        {
            _tokenHelper = new TokenHelper(endpoint, authKey, secretKey);
        }

        public DecryptionResponse DecryptTokenIntoRawUid(string token)
        {
            return _tokenHelper.Decrypt(token, DateTime.UtcNow, null, ClientType.Sharing);
        }

        public EncryptionDataResponse EncryptRawUidIntoToken(string rawUid)
        {
            return _tokenHelper.Encrypt(rawUid, DateTime.UtcNow);
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
