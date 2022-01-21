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
