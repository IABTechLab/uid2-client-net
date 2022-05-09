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
using System.Linq;
using UID2.Client.Utils;
using Newtonsoft.Json.Linq;

namespace UID2.Client
{
    internal static class KeyParser
    {
        /// <summary>
        /// Parse json data and load keys
        /// </summary>
        internal static KeyContainer Parse(string json)
        {
            return Parse(JObject.Parse(json));
        }

        /// <summary>
        /// Parse json data and load keys
        /// </summary>
        internal static KeyContainer Parse(JObject json)
        {
            var body = json.Value<JArray>("body");

            var keys = body.Select(i => (JObject)i).Select(item => new Key(
                    item.Value<long>("id"),
                    item.Value<int>("site_id"),
                    DateTimeUtils.FromEpochSeconds(item.Value<long>("created")),
                    DateTimeUtils.FromEpochSeconds(item.Value<long>("activates")),
                    DateTimeUtils.FromEpochSeconds(item.Value<long>("expires")),
                    Convert.FromBase64String(item.Value<string>("secret"))
                )).ToList();

            return new KeyContainer(keys);
        }
    }
}
