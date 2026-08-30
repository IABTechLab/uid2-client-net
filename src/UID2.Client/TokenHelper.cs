using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Threading;

namespace UID2.Client
{
    internal class TokenHelper
    {
        private readonly Uid2ClientHelper _uid2ClientHelper;
        private KeyContainer _container;

        internal TokenHelper(string endpoint, string authKey, string secretKey)
        {
            _uid2ClientHelper = new Uid2ClientHelper(endpoint, authKey, secretKey);
        }

        internal static DecryptionResponse TokenDetailsToDecryptionResponse(TokenDetails tokenDetails)
        {
            string uid = tokenDetails.idString; //todo, some errors should blank this out
            int siteKeySiteId = 0; //todo

            return new DecryptionResponse(tokenDetails.decryptionStatus, uid, tokenDetails.established, tokenDetails.siteId, siteKeySiteId, tokenDetails.identityType, tokenDetails.tokenVersion,
                tokenDetails.privacyBits?.IsClientSideGenerated, tokenDetails.expiry);
        }

        internal DecryptionResponse Decrypt(string token, DateTime now, string domainOrAppNameFromBidRequest, ClientType clientType)
        {
            var tokenDetails = DecryptTokenDetails(token, now, domainOrAppNameFromBidRequest, clientType);
            return TokenDetailsToDecryptionResponse(tokenDetails);
        }

        internal TokenDetails DecryptTokenDetails(string token, DateTime now, string domainOrAppNameFromBidRequest, ClientType clientType)
        {
            var container = Volatile.Read(ref _container);
            if (container == null)
            {
                return new TokenDetails(DecryptionStatus.NotInitialized);
            }

            if (!container.IsValid(now))
            {
                return new TokenDetails(DecryptionStatus.KeysNotSynced);
            }

            try
            {
                return UID2Encryption.DecryptTokenDetails(token, container, now, domainOrAppNameFromBidRequest, container.IdentityScope, clientType);
            }
            catch (Exception)
            {
                return new TokenDetails(DecryptionStatus.InvalidPayload);
            }
        }


        internal EncryptionDataResponse Encrypt(string rawUid, DateTime now)
        {
            var container = Volatile.Read(ref _container);
            if (container == null)
            {
                return EncryptionDataResponse.MakeError(EncryptionStatus.NotInitialized);
            }
            else if (!container.IsValid(now))
            {
                return EncryptionDataResponse.MakeError(EncryptionStatus.KeysNotSynced);
            }

            return UID2Encryption.Encrypt(rawUid, container, container.IdentityScope, now);
        }

        internal RefreshResponse Refresh(string urlSuffix)
        {
            return RefreshInternal(urlSuffix).Result;
        }

        private async Task<RefreshResponse> RefreshInternal(string urlSuffix)
        {
            try
            {
                var results = await _uid2ClientHelper.PostRequest(urlSuffix);
                Volatile.Write(ref _container, KeyParser.Parse(results.responseString));
                return RefreshResponse.MakeSuccess();
            }
            catch (HttpRequestException webEx)
            {
                return RefreshResponse.MakeError($"Web error: {webEx.Message}");
            }
            catch (Exception parserEx)
            {
                return RefreshResponse.MakeError(parserEx.Message);
            }
        }

        internal RefreshResponse RefreshJson(string json)
        {
            try
            {
                Volatile.Write(ref _container, KeyParser.Parse(json));
                return RefreshResponse.MakeSuccess();
            }
            catch (Exception e)
            {
                return RefreshResponse.MakeError(e.Message);
            }
        }


    }
}
