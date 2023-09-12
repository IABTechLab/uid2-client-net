using System;
using System.Collections;
using System.Collections.Specialized;

namespace UID2.Client
{
    readonly struct PrivacyBits
    {
        // Bit 0 is legacy and is no longer in use
        private const int CstgMask = 2;
        private const int CstgOptOutMask = 4;
        
        private readonly BitVector32 _bits;

        public PrivacyBits(int bitsAsInt)
        {
            _bits = new BitVector32(bitsAsInt);
        }

        // `_bits[x]` applies bit mask x to _bits, this is not indexing 
        public bool IsCstgDerived => _bits[CstgMask];

        public bool IsOptedOut => _bits[CstgOptOutMask];
    }
}