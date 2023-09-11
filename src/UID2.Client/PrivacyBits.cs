using System;
using System.Collections;

namespace UID2.Client
{
    public class PrivacyBits
    {
        // Bit 0 is legacy and is no longer in use
        private const int BitCstg = 1;
        private const int BitCstgOptOut = 2;
        
        private readonly BitArray _bits;

        public PrivacyBits(int bitsAsInt)
        {
            _bits = new BitArray(new [] {bitsAsInt});
        }

        public bool IsCstgDerived => _bits.Get(BitCstg);

        public bool IsOptedOut => _bits.Get(BitCstgOptOut);
    }
}