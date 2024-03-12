using System;
using System.Threading;
using System.Threading.Tasks;

namespace UID2.Client
{
    /// <summary>
    /// Client for interacting with UID2 services.
    /// </summary>
    [Obsolete("Please use BidstreamClient or SharingClient instead")]
    public interface IUID2Client
    {
        /// <summary>
        /// This will synchronously connect to the corresponding UID2 service and fetch the latest
        /// set of encryption keys which can then be used to decrypt advertising tokens using
        /// the decrypt_token function.
        /// </summary>
        /// <returns>Response indicating whether the refresh is successful or not</returns>
        RefreshResponse Refresh();

        /// <summary>
        /// Load the keys in the param json into the client
        /// </summary>
        /// <param name="json"></param>
        /// <returns>a response indicating if the refresh is successful</returns>
        [Obsolete("Please use Refresh() instead.")]
        RefreshResponse RefreshJson(string json);

        Task<RefreshResponse> RefreshAsync(CancellationToken token = default);

        /// <summary>
        /// Decrypt advertising token to extract UID2 details.
        /// </summary>
        /// <param name="token">The UID2 Token </param>
        /// <param name="now">At what UTC time this token is being decrypted</param>
        /// <returns>Response showing if decryption is successful and the resulting UID if successful.
        /// Or it could return error codes/string indicating what went wrong
        /// </returns>
        [Obsolete("Please use Decrypt(string token) instead.")]
        DecryptionResponse Decrypt(string token, DateTime utcNow);
        DecryptionResponse Decrypt(string token);
        /// <summary>
        /// Decrypt advertising token to extract UID2 details and does a domain name check with the provided domainNameFromBidRequest param
        /// for tokens from Client Side Token Generation 
        /// </summary>
        /// <param name="token">The UID2 Token </param>
        /// <param name="domainNameFromBidRequest">The domain name from bid request which should match the domain name of the publisher (registered with UID2 admin)
        /// generating this token previously using Client Side Token Generation
        /// </param>
        /// <returns>Response showing if decryption is successful and the resulting UID if successful.
        /// Or it could return error codes/string indicating what went wrong (such as DecryptionStatus.DomainNameCheckFailed)
        /// </returns>
        DecryptionResponse Decrypt(string token, string domainNameFromBidRequest);

        EncryptionDataResponse Encrypt(string rawUid);
        [Obsolete("Please use Encrypt(string rawUid) instead.")]
        EncryptionDataResponse EncryptData(EncryptionDataRequest request);

        [Obsolete("Please use Decrypt(string token) instead.")]
        DecryptionDataResponse DecryptData(string encryptedData);
    }

#pragma warning disable CS0618 //warning CS0618: 'UID2Client' is obsolete: 'Please use BidstreamClient or SharingClient instead'
    public class UID2ClientFactory
    {
        public static IUID2Client Create(string endpoint, string authKey, string secretKey)
        {
            return new UID2Client(endpoint, authKey, secretKey, IdentityScope.UID2);
        }
    }

    public class EUIDClientFactory
    {
        public static IUID2Client Create(string endpoint, string authKey, string secretKey)
        {
            return new UID2Client(endpoint, authKey, secretKey, IdentityScope.EUID);
        }
    }
}
