using System;

namespace UID2.Client
{
    public readonly struct DecryptionResponse
    {
        private readonly DecryptionStatus _status;
        private readonly string _uid;
        private readonly DateTime? _established;
        private readonly int? _siteId;
        private readonly int? _siteKeySiteId;

        public DecryptionResponse(DecryptionStatus status, string uid, DateTime? established, int? siteId, int? siteKeySiteId, bool? isCstgDerived)
        {
            _status = status;
            _uid = uid;
            _established = established;
            _siteId = siteId;
            _siteKeySiteId = siteKeySiteId;
            IsCstgDerived = isCstgDerived;
        }

        public static DecryptionResponse MakeError(DecryptionStatus status)
        {
            return new DecryptionResponse(status, null, null, null, null, null);
        }

        public bool Success => _status == DecryptionStatus.Success;
        public DecryptionStatus Status => _status;
        public string Uid => _uid;
        public DateTime? Established => _established;
        public int? SiteId => _siteId;
        public int? SiteKeySiteId => _siteKeySiteId;
        public bool? IsCstgDerived { get; }
    }
}
