using System;
using System.Collections.Generic;
using System.Text;

namespace UID2.Client
{
    public class Key
    {
        private readonly long _id;
        private readonly int _siteId;  //for legacy /key/latest
        private readonly int _keysetId;
        private readonly DateTime _created;
        private readonly DateTime _activates;
        private readonly DateTime _expires;
        private readonly byte[] _secret;

        public Key(long id, int siteId, DateTime created, DateTime activates, DateTime expires, byte[] secret)
        {   //for legacy /key/latest
            _id = id;
            _siteId = siteId;
            _created = created;
            _activates = activates;
            _expires = expires;
            _secret = secret;
        }

        public static Key CreateKeysetKey(long id, int keysetId, DateTime created, DateTime activates, DateTime expires, byte[] secret)
        {
            return new Key(id, created, activates, expires, secret, keysetId);
        }

        private Key(long id, DateTime created, DateTime activates, DateTime expires, byte[] secret, int keysetId)
        {
            _id = id;
            _keysetId = keysetId;
            _created = created;
            _activates = activates;
            _expires = expires;
            _secret = secret;
        }

    
        public long Id => _id;
        public int SiteId => _siteId;
        public int KeysetId => _keysetId;
        public DateTime Created => _created;
        public DateTime Activates => _activates;
        public DateTime Expires => _expires;
        public byte[] Secret => _secret;

        public bool IsActive(DateTime asOf)
        {
            return _activates <= asOf && asOf < _expires;
        }
    }

    public class KeysetKey
    {
        private readonly long _id;
        private readonly int _keysetId;
        private readonly DateTime _created;
        private readonly DateTime _activates;
        private readonly DateTime _expires;
        private readonly byte[] _secret;

        public KeysetKey(long id, int keysetId, DateTime created, DateTime activates, DateTime expires, byte[] secret)
        {
            _id = id;
            _keysetId = keysetId;
            _created = created;
            _activates = activates;
            _expires = expires;
            _secret = secret;
        }

        public long Id => _id;
        public int KeysetId => _keysetId;
        public DateTime Created => _created;
        public DateTime Activates => _activates;
        public DateTime Expires => _expires;
        public byte[] Secret => _secret;

        public bool IsActive(DateTime asOf)
        {
            return _activates <= asOf && asOf < _expires;
        }
    }

}
