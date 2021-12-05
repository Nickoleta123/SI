using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace lab1
{
    class Program
    {
        static void Main(string[] args)
        {
            EncryptDecript();
            EncryptDecript();
        }

        static void EncryptDecript()
        {
            Console.WriteLine("\nTextul pentru criptare: ");
            var textToEncrypt = Console.ReadLine();

            Console.WriteLine("Key: ");
            var key = Console.ReadLine();

            byte[] byteKey = Encoding.ASCII.GetBytes(key);

            using (Aes aes = Aes.Create())
            {
                byte[] encrypted = EncryptStringToBytes_Aes(textToEncrypt, byteKey, aes.IV);

                Console.WriteLine("Textul a fost criptat cu succes!");

                Console.WriteLine("Introduceti key pentru decriptare");
                var decryptKey = Console.ReadLine();

                byte[] decryptByteKey = Encoding.ASCII.GetBytes(decryptKey);

                string roundtrip = DecryptStringFromBytes_Aes(encrypted, decryptByteKey, aes.IV);

                Console.WriteLine("\n\nText necriptat: {0}", textToEncrypt);
                Console.WriteLine("Text criptat: {0}", Encoding.Default.GetString(encrypted));
                Console.WriteLine("Text decriptat: {0}", roundtrip);
            }
        }

        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] key, byte[] iv)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("key");
            if (iv == null || iv.Length <= 0)
                throw new ArgumentNullException("iv");

            byte[] encrypted;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                        {
                            streamWriter.Write(plainText);
                        }
                        encrypted = memoryStream.ToArray();
                    }
                }
            }

            return encrypted;
        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] key, byte[] iv)
        {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("key");
            if (iv == null || iv.Length <= 0)
                throw new ArgumentNullException("iv");

            string plaintext = null;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            try
                            {
                                plaintext = srDecrypt.ReadToEnd();
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine("Key incorecta.");
                                return "Textul nu a fost decriptat";
                            }
                        }
                    }
                }
            }

            return plaintext;
        }
    }
}
