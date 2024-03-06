using UID2.Client.Test.builder;
using UID2.Client;
using Xunit;

namespace UID2.Client.Test
{
    public abstract class PrivacyBitsTests
    {
        public class ReadsClientSideGeneratedBit
        {
            [Fact]
            public void WhenFalse()
            {
                var bits = PrivacyBitsBuilder.Builder().WithAllFlagsEnabled().WithClientSideGenerated(false).Build();
                Assert.False(new PrivacyBits(bits).IsClientSideGenerated);
            }

            [Fact]
            public void WhenTrue()
            {
                var bits = PrivacyBitsBuilder.Builder().WithAllFlagsDisabled().WithClientSideGenerated(true).Build();
                Assert.True(new PrivacyBits(bits).IsClientSideGenerated);
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