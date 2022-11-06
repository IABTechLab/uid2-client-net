namespace UID2.Client.Utils
{
    internal struct ByteArraySlice
    {
        public byte[] Buffer;
        public int Offset;
        public int Count;

        public ByteArraySlice(byte[] buffer, int offset, int count)
        {
            Buffer = buffer;
            Offset = offset;
            Count = count;
        }
    }
}
