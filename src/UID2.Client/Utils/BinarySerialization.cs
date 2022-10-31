using System;
using System.IO;
using System.Text;

namespace UID2.Client.Utils
{
    internal class BigEndianByteReader : BinaryReader
    {
        public BigEndianByteReader(Stream input) : base(input)
        {
        }

        public BigEndianByteReader(Stream input, Encoding encoding) : base(input, encoding)
        {
        }

        public BigEndianByteReader(Stream input, Encoding encoding, bool leaveOpen) : base(input, encoding, leaveOpen)
        {
        }

        public override int ReadInt32()
        {
            var data = base.ReadBytes(4);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(data);
            }
            return BitConverter.ToInt32(data, 0);
        }

        public override long ReadInt64()
        {
            var data = base.ReadBytes(8);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(data);
            }
            return BitConverter.ToInt64(data, 0);
        }
    }

    internal class BigEndianByteWriter : BinaryWriter
    {
        public BigEndianByteWriter(Stream output) : base(output)
        {
        }

        public BigEndianByteWriter(Stream output, Encoding encoding) : base(output, encoding)
        {
        }

        public BigEndianByteWriter(Stream output, Encoding encoding, bool leaveOpen) : base(output, encoding, leaveOpen)
        {
        }

        public override void Write(int i)
        {
            var data = BitConverter.GetBytes(i);
            Array.Reverse(data);
            base.Write(data);
        }

        public override void Write(long l)
        {
            var data = BitConverter.GetBytes(l);
            Array.Reverse(data);
            base.Write(data);
        }
    }
}
