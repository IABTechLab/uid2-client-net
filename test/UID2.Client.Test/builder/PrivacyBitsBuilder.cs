using System.Collections;

namespace uid2_client.test.builder
{
    public class PrivacyBitsBuilder
    {
        private bool _legacyBit; // first bit, doesn't have a meaning any more
        private bool _isCstgDerived;
        private bool _isOptedOut;

        public static PrivacyBitsBuilder Builder()
        {
            return new PrivacyBitsBuilder();
        }

        public PrivacyBitsBuilder WithAllFlagsEnabled()
        {
            _legacyBit = true;
            _isCstgDerived = true;
            _isOptedOut = true;

            return this;
        }

        public PrivacyBitsBuilder WithAllFlagsDisabled()
        {
            _legacyBit = false;
            _isCstgDerived = false;
            _isOptedOut = false;

            return this;
        }

        public PrivacyBitsBuilder WithCstgDerived(bool isCstgDerived)
        {
            _isCstgDerived = isCstgDerived;
            return this;
        }

        public PrivacyBitsBuilder WithOptedOut(bool isOptedOut)
        {
            _isOptedOut = isOptedOut;
            return this;
        }

        public int Build()
        {
            return FlagsToInt(new[] { _legacyBit, _isCstgDerived, _isOptedOut });
        }

        private static int FlagsToInt(bool[] flags)
        {
            BitArray bitArray = new BitArray(flags);
            int[] array = new int[1];
            bitArray.CopyTo(array, 0);
            return array[0];
        }
    }
}