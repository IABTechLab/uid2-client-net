using uid2_client.test.builder;
using UID2.Client;
using Xunit;

namespace uid2_client.test
{
    public abstract class PrivacyBitsTests
    {
        public class ReadsCstgBit
        {
            [Fact]
            public void WhenFalse()
            {
                var bits = PrivacyBitsBuilder.Builder().WithAllFlagsEnabled().WithCstgDerived(false).Build();
                Assert.False(new PrivacyBits(bits).IsCstgDerived);
            }

            [Fact]
            public void WhenTrue()
            {
                var bits = PrivacyBitsBuilder.Builder().WithAllFlagsDisabled().WithCstgDerived(true).Build();
                Assert.True(new PrivacyBits(bits).IsCstgDerived);
            }
        }

        public class ReadsOptedOutBit
        {
            [Fact]
            public void WhenFalse()
            {
                var bits = PrivacyBitsBuilder.Builder().WithAllFlagsEnabled().WithOptedOut(false).Build();
                Assert.False(new PrivacyBits(bits).IsOptedOut);
            }

            [Fact]
            public void WhenTrue()
            {
                var bits = PrivacyBitsBuilder.Builder().WithAllFlagsDisabled().WithOptedOut(true).Build();
                Assert.True(new PrivacyBits(bits).IsOptedOut);
            }
        }
    }
}