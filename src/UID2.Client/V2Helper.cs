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

using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Text;
using UID2.Client.Utils;

namespace UID2.Client
{
    internal static class V2Helper
    {
        private static (byte[], byte[]) MakePayload(DateTime now)
        {
            var ms = new MemoryStream(16);
            var writer = new BigEndianByteWriter(ms);
            writer.Write(DateTimeUtils.DateTimeToEpochMilliseconds(now));
            var nonce = new byte[8];
            ThreadSafeRandom.PerThread.NextBytes(nonce);
            ms.Write(nonce, 0, nonce.Length);
            return (ms.ToArray(), nonce);
        }

        internal static (string, byte[]) MakeEnvelope(byte[] secret, DateTime now)
        {
            var (payload, nonce) = MakePayload(now);
            var (iv, encrypted) = UID2Encryption.EncryptGCM(payload, secret);
            var envelope = new byte[1 + iv.Length + encrypted.Length];
            envelope[0] = 1;
            Array.Copy(iv, 0, envelope, 1, iv.Length);
            Array.Copy(encrypted, 0, envelope, 1 + iv.Length, encrypted.Length);
            var encodedEnvelope = Convert.ToBase64String(envelope);
            return (encodedEnvelope, nonce);
        }

        internal static JObject ParseResponse(string envelope, byte[] secret, byte[] nonce)
        {
            var envelopeBytes = Convert.FromBase64String(envelope);
            var payload = UID2Encryption.DecryptGCM(new ByteArraySlice(envelopeBytes, 0, envelopeBytes.Length), secret);
            var response = JObject.Parse(Encoding.UTF8.GetString(payload));
            var nonceString = Convert.ToBase64String(nonce);
            if (response.Value<string>("nonce") != nonceString)
            {
                throw new InvalidDataException("nonce mismatch");
            }

            return response;
        }
    }
}
