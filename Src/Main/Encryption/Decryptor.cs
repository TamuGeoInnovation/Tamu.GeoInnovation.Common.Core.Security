using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace USC.GISResearchLab.Common.Security.Encryption
{

    // code is from: http://msdn.microsoft.com/en-us/library/aa302405.aspx

    /// <summary>
    /// Summary description for Decryptor
    /// </summary>
    public class Decryptor
    {

        #region Properties

        private DecryptTransformer transformer;
        private byte[] initVec;

        public byte[] IV
        {
            set { initVec = value; }
        }


        #endregion

        public Decryptor(EncryptionAlgorithm algId)
        {
            transformer = new DecryptTransformer(algId);
        }

        public string DecryptToString(byte[] bytesData, byte[] bytesKey, byte[] initVec)
        {
            byte[] dec = Decrypt(bytesData, bytesKey, initVec);
            return Encoding.ASCII.GetString(dec);
        }

        public string DecryptBase64ToString(string bytesData, byte[] bytesKey, byte[] initVec)
        {
            byte[] dec = Decrypt(Convert.FromBase64String(bytesData), bytesKey, initVec);
            return Encoding.ASCII.GetString(dec);
        }

        public byte[] Decrypt(byte[] bytesData, byte[] bytesKey, byte[] initVec)
        {
            MemoryStream memStreamDecryptedData = new MemoryStream();

            transformer.IV = initVec;
            ICryptoTransform transform = transformer.GetCryptoServiceProvider(bytesKey, initVec);
            CryptoStream decStream = new CryptoStream(memStreamDecryptedData, transform, CryptoStreamMode.Write);
            try
            {
                decStream.Write(bytesData, 0, bytesData.Length);
            }
            catch (Exception ex)
            {
                throw new Exception("Error while writing encrypted data to the stream: \n" + ex.Message);
            }
            decStream.FlushFinalBlock();
            decStream.Close();


            return memStreamDecryptedData.ToArray();
        }
    }
}