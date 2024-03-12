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
            return DecryptTokenIntoRawUid(token, DateTime.UtcNow);
        }

        internal DecryptionResponse DecryptTokenIntoRawUid(string token, DateTime utcNow)
        {
            return _tokenHelper.Decrypt(token, utcNow, null, ClientType.Sharing);
        }


        public EncryptionDataResponse EncryptRawUidIntoToken(string rawUid)
        {
            return EncryptRawUidIntoToken(rawUid, DateTime.UtcNow);
        }

        internal EncryptionDataResponse EncryptRawUidIntoToken(string rawUid, DateTime utcNow)
        {
            return _tokenHelper.Encrypt(rawUid, utcNow);
        }

        public RefreshResponse Refresh()
        {
            return _tokenHelper.Refresh("/v2/key/sharing");
        }

        internal RefreshResponse RefreshJson(string json)
        {
            return _tokenHelper.RefreshJson(json);
        }
    }
}
