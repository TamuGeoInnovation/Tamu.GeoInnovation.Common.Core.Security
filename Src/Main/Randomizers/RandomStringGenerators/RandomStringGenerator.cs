using System;
using System.Security.Cryptography;

namespace USC.GISResearchLab.Common.Core.Randomizers.RandomStringGenerators
{
    public class RandomStringGenerator
    {
        public string CreateRandomString(int length)
        {
            string ret = "";
            try
            {
                byte[] rnd = new byte[length];
                RNGCryptoServiceProvider r = new RNGCryptoServiceProvider();
                r.GetBytes(rnd);
                ret = Convert.ToBase64String(rnd);
            }
            catch (Exception e)
            {
                throw new Exception("Exception occurred CreateRandomString", e);
            }
            return ret;
        }
    }
}
