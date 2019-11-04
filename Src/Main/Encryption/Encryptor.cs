using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace USC.GISResearchLab.Common.Security.Encryption
{

    // code is from: http://msdn.microsoft.com/en-us/library/aa302405.aspx

    /// <summary>
    /// Summary description for Encryptor
    /// </summary>
    public class Encryptor
    {
        #region Properties

        private EncryptTransformer transformer;
        private byte[] initVec;
        private byte[] encKey;

        public byte[] IV
        {
            get { return initVec; }
            set { initVec = value; }
        }

        public byte[] Key
        {
            get { return encKey; }
        }

        #endregion

        public Encryptor(EncryptionAlgorithm algId)
        {
            transformer = new EncryptTransformer(algId);
        }

        public byte[] EncryptString(string s, byte[] bytesKey, byte[] initVec)
        {
            return Encrypt(Encoding.ASCII.GetBytes(s), bytesKey, initVec);
        }

        public string EncryptStringToBase64(string s, byte[] bytesKey, byte[] initVec)
        {
            return Convert.ToBase64String(Encrypt(Encoding.ASCII.GetBytes(s), bytesKey, initVec));
        }

        public byte[] Encrypt(byte[] bytesData, byte[] bytesKey, byte[] initVec)
        {
            MemoryStream memStreamEncryptedData = new MemoryStream();

            transformer.IV = initVec;
            ICryptoTransform transform = transformer.GetCryptoServiceProvider(bytesKey, initVec);
            CryptoStream encStream = new CryptoStream(memStreamEncryptedData, transform, CryptoStreamMode.Write);
            try
            {
                encStream.Write(bytesData, 0, bytesData.Length);
            }
            catch (Exception ex)
            {
                throw new Exception("Error while writing encrypted data to the stream: \n" + ex.Message);
            }

            encKey = transformer.Key;
            encStream.FlushFinalBlock();
            encStream.Close();

            return memStreamEncryptedData.ToArray();
        }
    }
}