using System.Security.Cryptography;

namespace USC.GISResearchLab.Common.Core.Randomizers.RandomNumbers
{
    public class RandomNumberGenerator
    {

        public static int GetRandomNumber()
        {
            int ret = 0;
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();

            byte[] randomNumber = new byte[1];

            rngCsp.GetBytes(randomNumber);
            ret = (int)randomNumber[0];

            return ret;
        }
    }
}
