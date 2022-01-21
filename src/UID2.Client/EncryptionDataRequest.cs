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
