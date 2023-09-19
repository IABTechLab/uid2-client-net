using Microsoft.IdentityModel.Tokens;

namespace UID2.Client
{
    //always use this interface to encode/decode Base64URL standard with no padding 
    //as specified on https://www.rfc-editor.org/rfc/rfc4648#section-5
    //as unit test assumes that we are testing the encoding/decoding lib used here
    public class UID2Base64UrlCoder
    {
        public static string Encode(byte[] bytes)
        {
            return Base64UrlEncoder.Encode(bytes);
        }
        
        public static byte[] Decode(string str)
        {
            return Base64UrlEncoder.DecodeBytes(str);
        }
    }
}