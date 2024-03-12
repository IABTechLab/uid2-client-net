using Xunit;

namespace UID2.Client.Test.builder
{
    public class PrivacyBitsBuilderTest
    {
        private readonly PrivacyBitsBuilder _builder = PrivacyBitsBuilder.Builder();
        
        [Fact]
        public void WithAllFlagsEnabled()
        {
            var privacyBits = _builder.WithAllFlagsEnabled().Build();
            Assert.Equal(7, privacyBits);
        }
        
        [Fact]
        public void WithAllFlagsDisabled()
        {
            var privacyBits = _builder.WithAllFlagsDisabled().Build();
            Assert.Equal(0, privacyBits);
        }

        [Fact]
        public void AllDisabledByDefault()
        {
            var privacyBits = _builder.Build();
            Assert.Equal(0, privacyBits);
        }
        
        [Theory]
        [InlineData(true, true, 6)]
        [InlineData(false, false, 0)]
        [InlineData(true, false, 2)]
        [InlineData(false, true, 4)]
        public void SetsPrivacyBitCombinations(bool isClientSideGenerated, bool isOptedOut, int expected)
        {
            var privacyBits = _builder.WithOptedOut(isOptedOut).WithClientSideGenerated(isClientSideGenerated).Build();
            Assert.Equal(expected, privacyBits);
        }
    }
}