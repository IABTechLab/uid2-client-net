using System;

namespace UID2.Client
{
    public readonly struct DecryptionResponse
    {
        public DecryptionResponse(DecryptionStatus status, string uid, DateTime? established, int? siteId, int? siteKeySiteId, bool? isCstgDerived)
        {
            Status = status;
            Uid = uid;
            Established = established;
            SiteId = siteId;
            SiteKeySiteId = siteKeySiteId;
            IsCstgDerived = isCstgDerived;
        }

        public static DecryptionResponse MakeError(DecryptionStatus status)
        {
            return new DecryptionResponse(status, null, null, null, null, null);
        }

        public bool Success => Status == DecryptionStatus.Success;
        public DecryptionStatus Status { get; }
        public string Uid { get; }
        public DateTime? Established { get; }
        public int? SiteId { get; }
        public int? SiteKeySiteId { get; }
        public bool? IsCstgDerived { get; }
    }
}
