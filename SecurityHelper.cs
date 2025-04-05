using System.Text;
using System.Security.Cryptography;

namespace PasswordResetPortal
{
    public static class SecurityHelper
    {
        /// <summary>
        /// Encrypt a piece of text using key supplied.  Use randomly generated initialization vector to prevent identical plain texts from having identical output
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static string Encrypt(string plainText, string key)
        {
            var buffer = Encoding.UTF8.GetBytes(plainText);
            var iv = GetRandomData(128);
            var keyArray = new byte[32];
            var incomingKeyArray = Encoding.ASCII.GetBytes(key);

            //Take up to the first 32 bytes of data as key
            if(incomingKeyArray.Length <= keyArray.Length)
                Buffer.BlockCopy(incomingKeyArray, 0, keyArray, 0, incomingKeyArray.Length);
            else
                Buffer.BlockCopy(incomingKeyArray, 0, keyArray, 0, keyArray.Length);

            byte[] result;
            using (var aes = Aes.Create())
            {
                aes.Key = keyArray;
                aes.IV = iv;
                aes.Padding = PaddingMode.PKCS7;

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                using (var resultStream = new MemoryStream())
                {
                    using (var aesStream = new CryptoStream(resultStream, encryptor, CryptoStreamMode.Write))
                    using (var plainStream = new MemoryStream(buffer))
                    {
                        plainStream.CopyTo(aesStream);
                    }

                    result = resultStream.ToArray();
                }
            }

            //Create new array with the initialization vector at the front
            var retVal = new byte[iv.Length + result.Length];
            Buffer.BlockCopy(iv, 0, retVal, 0, iv.Length);
            Buffer.BlockCopy(result, 0, retVal, iv.Length, result.Length);

            return Convert.ToBase64String(retVal);
        }

        /// <summary>
        /// Take a coded text and convert back to plain text using key supplied
        /// </summary>
        /// <param name="cryptText"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static string Decrypt(string cryptText, string key)
        {
            var cryptArray = Convert.FromBase64String(cryptText);
            var result = "";
            var keyArray = new byte[32];
            var incomingKeyArray = Encoding.ASCII.GetBytes(key);

            //Take up to the first 32 bytes of data as key
            if (incomingKeyArray.Length <= keyArray.Length)
                Buffer.BlockCopy(incomingKeyArray, 0, keyArray, 0, incomingKeyArray.Length);
            else
                Buffer.BlockCopy(incomingKeyArray, 0, keyArray, 0, keyArray.Length);

            using (var aes = Aes.Create())
            {
                aes.IV = new byte[16];
                var actualCryptArray = new byte[cryptArray.Length - aes.IV.Length];
                aes.Padding = PaddingMode.PKCS7;
                var iv = new byte[16];
                Buffer.BlockCopy(cryptArray, 0, iv, 0, iv.Length);
                Buffer.BlockCopy(cryptArray, aes.IV.Length, actualCryptArray, 0, cryptArray.Length - aes.IV.Length);

                aes.IV = iv;
                aes.Key = keyArray;

                using (var decryptor = aes.CreateDecryptor())
                using (var msStream = new MemoryStream(actualCryptArray))
                using (var csStream = new CryptoStream(msStream, decryptor, CryptoStreamMode.Read))
                using (var reader = new StreamReader(csStream))
                {
                    result = reader.ReadToEnd();
                }

            }

            return result;
        }

        /// <summary>
        /// Create a random set of data to be used for initialization vector
        /// </summary>
        /// <param name="bits"></param>
        /// <returns></returns>
        private static byte[] GetRandomData(int bits)
        {
            var result = new byte[bits / 8];
            RandomNumberGenerator.Create().GetBytes(result);
            return result;
        }
    }
}
