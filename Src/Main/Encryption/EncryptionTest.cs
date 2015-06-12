using System;
using System.Text;

namespace USC.GISResearchLab.Common.Security.Encryption
{

    // code is from: http://msdn.microsoft.com/en-us/library/aa302405.aspx

    /// <summary>
    /// Summary description for EncryptionTest
    /// </summary>
    public class EncryptionTest
    {
        public EncryptionTest()
        {
        }

        public void RunTest()
        {
            // Set the required algorithm
            EncryptionAlgorithm algorithm = EncryptionAlgorithm.Des;

            // Init variables.
            byte[] IV = null;
            byte[] cipherText = null;
            byte[] key = null;

            try
            {
                //Try to encrypt.
                //Create the encryptor.
                Encryptor enc = new Encryptor(EncryptionAlgorithm.Des);
                byte[] plainText = Encoding.ASCII.GetBytes("Test String");

                if ((EncryptionAlgorithm.TripleDes == algorithm) || (EncryptionAlgorithm.Rijndael == algorithm))
                {
                    //3Des only work with a 16 or 24 byte key.
                    key = Encoding.ASCII.GetBytes("password12345678");

                    if (EncryptionAlgorithm.Rijndael == algorithm)
                    {
                        // Must be 16 bytes for Rijndael.
                        IV = Encoding.ASCII.GetBytes("init vec is big.");
                    }
                    else
                    {
                        IV = Encoding.ASCII.GetBytes("init vec");
                    }
                }
                else
                {
                    //Des only works with an 8 byte key. The others uses variable length keys.
                    //Set the key to null to have a new one generated.
                    key = Encoding.ASCII.GetBytes("password");
                    IV = Encoding.ASCII.GetBytes("init vec");
                }

                // Uncomment the next lines to have the key or IV generated for you.
                // key = null;
                // IV = null;

                enc.IV = IV;

                // Perform the encryption.
                cipherText = enc.Encrypt(plainText, key, IV);
                // Retrieve the intialization vector and key. You will need it for decryption.
                IV = enc.IV;
                key = enc.Key;

                // Look at your cipher text and initialization vector.
                Console.WriteLine("Cipher text: " + Convert.ToBase64String(cipherText));
                Console.WriteLine("Initialization vector: " + Convert.ToBase64String(IV));
                Console.WriteLine("Key: " + Convert.ToBase64String(key));
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception encrypting. " + ex.Message);
                return;
            }
            try
            {
                //Try to decrypt.
                //Set up your decryption, give it the algorithm and initialization vector.

                Decryptor dec = new Decryptor(algorithm);
                dec.IV = IV;

                // Go ahead and decrypt.

                byte[] plainText = dec.Decrypt(cipherText, key, IV);
                // Look at your plain text.

                Console.WriteLine(" Plain text: " + Encoding.ASCII.GetString(plainText));
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception decrypting. " + ex.Message);
                return;


            }
        }
    }
}