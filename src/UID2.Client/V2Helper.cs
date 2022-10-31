using System;
using System.IO;
using System.Linq;
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

        internal static byte[] ParseResponse(string envelope, byte[] secret, byte[] nonce)
        {
            var envelopeBytes = Convert.FromBase64String(envelope);
            var payload = UID2Encryption.DecryptGCM(new ByteArraySlice(envelopeBytes, 0, envelopeBytes.Length), secret);
            var payloadReader = new BigEndianByteReader(new MemoryStream(payload));
            var respondedMilliseconds = payloadReader.ReadInt64();
            var receivedNonce = payloadReader.ReadBytes(nonce.Length);
            if (!Enumerable.SequenceEqual(receivedNonce, nonce))
            {
                throw new InvalidDataException("nonce mismatch");
            }

            return payloadReader.ReadBytes(payload.Length - 16);
        }
    }
}
