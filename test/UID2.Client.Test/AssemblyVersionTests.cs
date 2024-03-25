using Xunit;

namespace UID2.Client.Test
{
    public class AssemblyVersionTests 
    {
        [Fact]
        public void AssemblyHasVersionNumber()
        {
            Assert.True(float.Parse(UID2.Client.ThisAssembly.AssemblyVersion) > 0.9);
        }
    }
}