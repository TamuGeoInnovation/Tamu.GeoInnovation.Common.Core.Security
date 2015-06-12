using System.Security.Cryptography;

namespace USC.GISResearchLab.Common.Security.Encryption
{

    // code is from: http://msdn.microsoft.com/en-us/library/aa302405.aspx

    /// <summary>
    /// Summary description for DecryptTransformer
    /// </summary>
    internal class DecryptTransformer
    {
        #region Properties

        private EncryptionAlgorithm algorithmID;
        private byte[] initVec;

        internal byte[] IV
        {
            set { initVec = value; }
        }

        #endregion

        internal DecryptTransformer(EncryptionAlgorithm deCryptId)
        {
            algorithmID = deCryptId;
        }

        internal ICryptoTransform GetCryptoServiceProvider(byte[] bytesKey, byte[] initVec)
        {
            // Pick the provider.
            switch (algorithmID)
            {
                case EncryptionAlgorithm.Des:
                    {
                        DES des = new DESCryptoServiceProvider();
                        des.Mode = CipherMode.CBC;
                        des.Key = bytesKey;
                        des.IV = initVec;
                        return des.CreateDecryptor();
                    }
                case EncryptionAlgorithm.TripleDes:
                    {
                        TripleDES des3 = new TripleDESCryptoServiceProvider();
                        des3.Mode = CipherMode.CBC;
                        return des3.CreateDecryptor(bytesKey, initVec);
                    }
                case EncryptionAlgorithm.Rc2:
                    {
                        RC2 rc2 = new RC2CryptoServiceProvider();
                        rc2.Mode = CipherMode.CBC;
                        return rc2.CreateDecryptor(bytesKey, initVec);
                    }
                case EncryptionAlgorithm.Rijndael:
                    {
                        Rijndael rijndael = new RijndaelManaged();
                        rijndael.Mode = CipherMode.CBC;
                        return rijndael.CreateDecryptor(bytesKey, initVec);
                    }
                default:
                    {
                        throw new CryptographicException("Algorithm ID '" + algorithmID + "' not supported.");
                    }
            }
        }
    }
}