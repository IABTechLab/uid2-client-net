using System;
using System.Collections.Generic;
using System.Text;

namespace UID2.Client
{
    public class Key
    {
        private readonly long _id;
        private readonly int _siteId;
        private readonly DateTime _created;
        private readonly DateTime _activates;
        private readonly DateTime _expires;
        private readonly byte[] _secret;

        public Key(long id, int siteId, DateTime created, DateTime activates, DateTime expires, byte[] secret)
        {
            _id = id;
            _siteId = siteId;
            _created = created;
            _activates = activates;
            _expires = expires;
            _secret = secret;
        }

        public long Id => _id;
        public int SiteId => _siteId;
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
