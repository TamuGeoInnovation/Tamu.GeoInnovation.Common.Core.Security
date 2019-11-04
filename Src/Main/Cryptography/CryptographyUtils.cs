using System;
using System.Security.Cryptography;
using System.Text;
using System.Web.Security;

namespace USC.GISResearchLab.Common.Security.Cryptography
{

    // code partly from: http://msdn2.microsoft.com/en-us/library/aa302398.aspx
    // code partly from: http://msdn.microsoft.com/msdnmag/issues/04/09/SQLInjection/default.aspx?loc=&fig=true#fig9
    // code partly from: http://msdn.microsoft.com/msdnmag/issues/04/09/SQLInjection/


    public class CryptographyUtils
    {
        public static string CreateSalt(int size)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] buff = new byte[size];
            rng.GetNonZeroBytes(buff);
            return Convert.ToBase64String(buff).ToUpper();
        }

        public static string CreatePasswordHash(string pwd, string salt)
        {
            string saltAndPwd = null;
            //salt = "OPSHIPC=";
            if (string.IsNullOrEmpty(salt)) saltAndPwd = pwd;
            else saltAndPwd = String.Concat(pwd, salt);

            string hashedPwd = FormsAuthentication.HashPasswordForStoringInConfigFile(saltAndPwd, "SHA1");
            hashedPwd = String.Concat(hashedPwd, salt);
            return hashedPwd;
        }

        // from http://blogs.msdn.com/b/csharpfaq/archive/2006/10/09/how-do-i-calculate-a-md5-hash-from-a-string_3f00_.aspx
        public static string CalculateMD5Hash(string input)
        {
            // step 1, calculate MD5 hash from input
            MD5 md5 = System.Security.Cryptography.MD5.Create();
            byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(input);
            byte[] hash = md5.ComputeHash(inputBytes);

            // step 2, convert byte array to hex string
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hash.Length; i++)
            {
                sb.Append(hash[i].ToString("x2"));
            }
            return sb.ToString();
        }


        public static byte[] CalculateMD5HashAsBytes(string input)
        {
            // step 1, calculate MD5 hash from input
            MD5 md5 = System.Security.Cryptography.MD5.Create();
            byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(input);
            byte[] hash = md5.ComputeHash(inputBytes);
            return hash;
        }
    }
}
