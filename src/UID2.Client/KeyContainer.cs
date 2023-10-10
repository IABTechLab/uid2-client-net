using System;
using System.Collections.Generic;
using System.Linq;
using UID2.Client.Utils;

namespace UID2.Client
{
    internal class KeyContainer
    {
        private readonly Dictionary<long, Key> _keys;
        private readonly DateTime _latestKeyExpiry = DateTime.MinValue;

        private readonly Dictionary<int, List<Key>> _keysBySite = new Dictionary<int, List<Key>>(); //for legacy /key/latest

        private readonly Dictionary<int, List<Key>> _keysByKeyset = new Dictionary<int, List<Key>>();

        private readonly Dictionary<int, Site> _siteIdToSite = new Dictionary<int, Site>();

        private readonly int _callerSiteId;
        private readonly int _masterKeysetId;
        private readonly int _defaultKeysetId;
        private readonly long _tokenExpirySeconds;

        internal KeyContainer(List<Key> keys)
        {   //legacy /key/latest
            _keys = new Dictionary<long, Key>(keys.Count);
            foreach (var key in keys)
            {
                _keys.Add(key.Id, key);
                if (key.SiteId > 0)
                {
                    if (!_keysBySite.TryGetValue(key.SiteId, out var siteKeys))
                    {
                        siteKeys = new List<Key>();
                        _keysBySite.Add(key.SiteId, siteKeys);
                    }
                    siteKeys.Add(key);
                }

                if (key.Expires > _latestKeyExpiry)
                {
                    _latestKeyExpiry = key.Expires;
                }
            }

            foreach (var kv in _keysBySite)
            {
                kv.Value.Sort((Key a, Key b) => a.Activates.CompareTo(b.Activates));
            }
        }

        internal KeyContainer(int callerSiteId, int masterKeysetId, int defaultKeysetId, long tokenExpirySeconds, List<Key> keys, IEnumerable<Site> sites)
        {   //key/sharing
            _callerSiteId = callerSiteId;
            _masterKeysetId = masterKeysetId;
            _defaultKeysetId = defaultKeysetId;
            _tokenExpirySeconds = tokenExpirySeconds;


            _keys = new Dictionary<long, Key>(keys.Count);
            foreach (var key in keys)
            {
                _keys.Add(key.Id, key);
                if (key.KeysetId > 0)
                {
                    if (!_keysByKeyset.TryGetValue(key.KeysetId, out var keysetKeys))
                    {
                        keysetKeys = new List<Key>();
                        _keysByKeyset.Add(key.KeysetId, keysetKeys);
                    }
                    keysetKeys.Add(key);
                }

                if (key.Expires > _latestKeyExpiry)
                {
                    _latestKeyExpiry = key.Expires;
                }
            }

            foreach (var kv in _keysByKeyset)
            {
                kv.Value.Sort((Key a, Key b) => a.Activates.CompareTo(b.Activates));
            }

            this._siteIdToSite = sites.ToDictionary(site => site.Id, site => site);
        }

        public bool IsValid(DateTime asOf)
        {
            return asOf < _latestKeyExpiry;
        }

        public bool TryGetKey(long id, out Key key)
        {
            if (_keys.TryGetValue(id, out key))
            {
                return true;
            }

            return false;
        }

        public bool TryGetDefaultKey(DateTime now, out Key key)
        {
            return TryGetKeysetActiveKey(_defaultKeysetId, now, out key);
        }

        public bool TryGetMasterKey(DateTime now, out Key key)
        {
            return TryGetKeysetActiveKey(_masterKeysetId, now, out key);
        }

        public bool IsDomainNameAllowedForSite(int siteId, string domainName)
        {
            if (domainName == null)
            {
                return false;
            }
            
            return this._siteIdToSite.TryGetValue(siteId, out var site) && site.AllowDomainName(domainName);
        }

        private bool TryGetKeysetActiveKey(int keysetId, DateTime now, out Key key)
        {
            if (!_keysByKeyset.TryGetValue(keysetId, out var keyset) || keyset.Count == 0)
            {
                key = null;
                return false;
            }

            return TryGetLatestKey(keyset, now, out key);
        }

        private bool TryGetLatestKey(List<Key> keys, DateTime now, out Key key)
        {
            int it = ListUtils.UpperBound(keys, now, (DateTime ts, Key k) => ts < k.Activates);
            while (it > 0)
            {
                --it;
                key = keys[it];
                if (key.IsActive(now))
                {
                    return true;
                }
            }

            key = null;
            return false;
        }
    
        public bool TryGetActiveSiteKey(int siteId, DateTime now, out Key key)
        {
            if (!_keysBySite.TryGetValue(siteId, out var siteKeys) || siteKeys.Count == 0)
            {
                key = null;
                return false;
            }

            return TryGetLatestKey(siteKeys, now, out key);
        }

        public int CallerSiteId => _callerSiteId;
        public long TokenExpirySeconds => _tokenExpirySeconds;

    }
}