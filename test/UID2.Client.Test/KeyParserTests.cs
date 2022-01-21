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

using Xunit;
using System.IO;
using System.Text;
using UID2.Client.Utils;
using System;

namespace UID2.Client.Test
{
    public class KeyParserTests
    {
        [Fact]
        public void ParseKeyList()
        {
            var s =
                @"{""body"": [
                    {
                        ""id"": 3,
                        ""site_id"": 13,
                        ""created"": 1609459200,
                        ""activates"": 1609459210,
                        ""expires"": 1893456000,
                        ""secret"": ""o8HsvkwJ5Ulnrd0uui3GpukpwDapj+JLqb7qfN/GJKo=""
                    },
                    {
                        ""id"": 2,
                        ""site_id"": 14,
                        ""created"": 1609458200,
                        ""activates"": 1609459220,
                        ""expires"": 1893457000,
                        ""secret"": ""DD67xF8OFmbJ1/lMPQ6fGRDbJOT4kXErrYWcKdFfCUE=""
                    }
                ]}";

            var keyContainer = KeyParser.Parse(s);

            Key key;

            Assert.True(keyContainer.TryGetKey(3, out key));
            Assert.Equal(13, key.SiteId);
            Assert.Equal(DateTimeUtils.FromEpochSeconds(1609459200), key.Created);
            Assert.Equal(DateTimeUtils.FromEpochSeconds(1609459210), key.Activates);
            Assert.Equal(DateTimeUtils.FromEpochSeconds(1893456000), key.Expires);
            Assert.Equal("o8HsvkwJ5Ulnrd0uui3GpukpwDapj+JLqb7qfN/GJKo=", Convert.ToBase64String(key.Secret));

            Assert.True(keyContainer.TryGetKey(2, out key));
            Assert.Equal(14, key.SiteId);
            Assert.Equal(DateTimeUtils.FromEpochSeconds(1609458200), key.Created);
            Assert.Equal(DateTimeUtils.FromEpochSeconds(1609459220), key.Activates);
            Assert.Equal(DateTimeUtils.FromEpochSeconds(1893457000), key.Expires);
            Assert.Equal("DD67xF8OFmbJ1/lMPQ6fGRDbJOT4kXErrYWcKdFfCUE=", Convert.ToBase64String(key.Secret));
        }

        [Fact]
        public void ParseErrorKeyList()
        {
            Assert.ThrowsAny<Exception>(() => KeyParser.Parse(@"{""status"": ""error""}"));
            Assert.ThrowsAny<Exception>(() => KeyParser.Parse(@"{""body"": ""error""}"));
            Assert.ThrowsAny<Exception>(() => KeyParser.Parse(@"{""body"": [1, 2, 3]}"));
            Assert.ThrowsAny<Exception>(() => KeyParser.Parse(@"{""body"": [{}]}"));
            Assert.ThrowsAny<Exception>(() => KeyParser.Parse(@"{""body"": [{""id"": ""test""}]}"));
            Assert.ThrowsAny<Exception>(() => KeyParser.Parse(@"{""body"": [{""id"": 5}]}"));
        }
    }
}
