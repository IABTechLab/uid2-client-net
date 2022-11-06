using System;

namespace UID2.Client
{
    public struct EncryptionDataRequest
    {
        private byte[] _data;
        private int? _siteId;
        private Key _key;
        private string _advertisingToken;
        private byte[] _iv;
        private DateTime? _now;

        private EncryptionDataRequest(byte[] data)
        {
            _data = data;
            _siteId = null;
            _key = null;
            _advertisingToken = null;
            _iv = null;
            _now = null;
        }

        public static EncryptionDataRequest ForData(byte[] data)
        {
            return new EncryptionDataRequest(data);
        }

        public EncryptionDataRequest WithData(byte[] data) { _data = data; return this; }
        public EncryptionDataRequest WithSiteId(int? siteId) { _siteId = siteId; return this; }
        internal EncryptionDataRequest WithKey(Key key) { _key = key; return this; }
        public EncryptionDataRequest WithAdvertisingToken(string token) { _advertisingToken = token; return this; }
        public EncryptionDataRequest WithInitializationVector(byte[] iv) { _iv = iv; return this; }
        public EncryptionDataRequest WithNow(DateTime? now) { _now = now; return this; }

        public byte[] Data { get => _data; }
        public int? SiteId { get => _siteId; }
        internal Key Key { get => _key; }
        public string AdvertisingToken { get => _advertisingToken; }
        public byte[] InitializationVector { get => _iv; }
        public DateTime Now { get => _now ?? DateTime.UtcNow; }
    }
}
