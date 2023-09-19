using System.Collections;

namespace UID2.Client
{
    internal class PrivacyBits
    {
        // Bit 0 is legacy and is no longer in use
        private const int BitClientSideGenerated = 1;
        private const int BitOptedOut = 2;
        
        private readonly BitArray _bits;

        public PrivacyBits(int bitsAsInt)
        {
            _bits = new BitArray(new [] {bitsAsInt});
        }

        public bool IsClientSideGenerated => _bits.Get(BitClientSideGenerated);

        public bool IsOptedOut => _bits.Get(BitOptedOut);
    }
}