using System;

namespace UID2.Client
{
    public readonly struct DecryptionResponse
    {
        public DecryptionResponse(DecryptionStatus status, string uid, DateTime? established, int? siteId, int? siteKeySiteId, IdentityType? identityType, int? advertisingTokenVersion,
            bool? isClientSideGenerated = false)
        {
            Status = status;
            Uid = uid;
            Established = established;
            SiteId = siteId;
            SiteKeySiteId = siteKeySiteId;
            IdentityType = identityType;
            AdvertisingTokenVersion = advertisingTokenVersion;
            IsClientSideGenerated = isClientSideGenerated;
        }

        public static DecryptionResponse MakeError(DecryptionStatus status)
        {
            return new DecryptionResponse(status, null, null, null, null, null, null, null);
        }

        public bool Success => Status == DecryptionStatus.Success;
        public DecryptionStatus Status { get; }
        public string Uid { get; }
        public DateTime? Established { get; }
        public int? SiteId { get; }
        public int? SiteKeySiteId { get; }
        public IdentityType? IdentityType { get; }
        public int? AdvertisingTokenVersion { get; }
        public bool? IsClientSideGenerated { get; }
    }
}