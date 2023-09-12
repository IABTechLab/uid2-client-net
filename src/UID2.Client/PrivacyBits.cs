using System;
using System.Collections;
using System.Collections.Specialized;

namespace UID2.Client
{
    readonly struct PrivacyBits
    {
        // Bit 0 is legacy and is no longer in use
        private const int BitCstg = 1;
        private const int BitCstgOptOut = 2;
        
        private readonly BitVector32 _bits;

        public PrivacyBits(int bitsAsInt)
        {
            _bits = new BitVector32(bitsAsInt);
        }

        public bool IsCstgDerived => !_bits[BitCstg];

        public bool IsOptedOut => !_bits[BitCstgOptOut];
    }
}