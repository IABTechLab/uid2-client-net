// Copyright (c) 2021 The Trade Desk, Inc
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

using System;
using System.Collections.Generic;
using UID2.Client.Utils;

namespace UID2.Client
{
    internal class KeyContainer : IKeyContainer
    {
        private readonly Dictionary<long, Key> _keys;
        private readonly Dictionary<int, List<Key>> _keysBySite = new Dictionary<int, List<Key>>();
        private readonly DateTime _latestKeyExpiry = DateTime.MinValue;

        internal KeyContainer(List<Key> keys)
        {
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

        public bool TryGetActiveSiteKey(int siteId, DateTime now, out Key key)
        {
            if (!_keysBySite.TryGetValue(siteId, out var siteKeys) || siteKeys.Count == 0)
            {
                key = null;
                return false;
            }

            int it = ListUtils.UpperBound(siteKeys, now, (DateTime ts, Key k) => ts < k.Activates);
            while (it > 0)
            {
                --it;
                key = siteKeys[it];
                if (key.IsActive(now))
                {
                    return true;
                }
            }

            key = null;
            return false;
        }
    }
}