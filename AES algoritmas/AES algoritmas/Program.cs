using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main()
    {
        Console.WriteLine("AES Encryption and Decryption");
        Console.WriteLine("-----------------------------");
        Console.WriteLine("1. Encrypt");
        Console.WriteLine("2. Decrypt");
        Console.Write("Choose an option (1 or 2): ");
        string option = Console.ReadLine();

        if (option == "1")
        {
            Console.Write("Enter the plain text: ");
            string plainText = Console.ReadLine();

            Console.Write("Enter the key: ");
            string key = Console.ReadLine();

            byte[] encryptedData = EncryptAES(plainText, key);
            string encryptedBase64 = Convert.ToBase64String(encryptedData);

            Console.WriteLine("Encrypted Data (Base64): " + encryptedBase64);

            Console.Write("Do you want to save the encrypted data to a file? (Y/N): ");
            string saveToFile = Console.ReadLine();

            if (saveToFile.ToUpper() == "Y")
            {
                string filePath = @"C:\Users\Azuolynas\Desktop\AES algoritmas\Uzsifruotas textas.txt";

                SaveEncryptedDataToFile(filePath, plainText, key, encryptedBase64);
            }
        }
        else if (option == "2")
        {
            Console.Write("Enter the encrypted data (Base64): ");
            string encryptedBase64 = Console.ReadLine();

            Console.Write("Enter the key: ");
            string key = Console.ReadLine();

            byte[] encryptedData;
            try
            {
                encryptedData = Convert.FromBase64String(encryptedBase64);
            }
            catch (FormatException)
            {
                Console.WriteLine("Invalid Base64 input. Exiting the program.");
                return;
            }

            string decryptedText = DecryptAES(encryptedData, key);

            Console.WriteLine("Decrypted Text: " + decryptedText);
        }
        else
        {
            Console.WriteLine("Invalid option. Exiting the program.");
        }
    }

    // Encrypts the plain text using AES algorithm with a given key
    static byte[] EncryptAES(string plainText, string key)
    {
        byte[] salt = Encoding.UTF8.GetBytes("SaltySalt"); // Salt value for password-based key derivation
        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

        using (var aes = new AesCryptoServiceProvider())
        {
            var passwordDerivedBytes = new Rfc2898DeriveBytes(key, salt, 10000);
            byte[] derivedKey = passwordDerivedBytes.GetBytes(aes.KeySize / 8);

            aes.Mode = CipherMode.CBC; //sets mode to CBC
            aes.Padding = PaddingMode.PKCS7; //sets the padding mode for the AES encryption algorithm to PKCS7. Padding is used in block ciphers like AES when the length of the input data is not a multiple of the block size
            aes.GenerateIV(); //generates a random Initialization Vector (IV) for the AES encryption algorithm.
            byte[] iv = aes.IV;
            //kodo blokas paima išvestinį raktą ir IV, sukuria šifratorių ir naudoja jį kartu su CryptoStream, kad atliktų AES šifravimą paprastuose baituose. Šifruoti duomenys saugomi MemoryStream, kuris vėliau konvertuojamas į baitų masyvą ir grąžinamas kaip šifruotas tekstas.
            using (var encryptor = aes.CreateEncryptor(derivedKey, iv))
            using (var ms = new MemoryStream())
            {
                ms.Write(iv, 0, iv.Length);

                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(plainBytes, 0, plainBytes.Length);
                    cs.FlushFinalBlock();
                }

                return ms.ToArray();
            }
        }
    }

    // Decrypts the encrypted data using AES algorithm with a given key
    static string DecryptAES(byte[] encryptedData, string key)
    {
        byte[] salt = Encoding.UTF8.GetBytes("SaltySalt"); // Salt value for password-based key derivation

        using (var aes = new AesCryptoServiceProvider())
        {
            var passwordDerivedBytes = new Rfc2898DeriveBytes(key, salt, 10000);
            byte[] derivedKey = passwordDerivedBytes.GetBytes(aes.KeySize / 8);

            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            byte[] iv = new byte[aes.BlockSize / 8];
            Array.Copy(encryptedData, 0, iv, 0, iv.Length);

            byte[] cipherBytes = new byte[encryptedData.Length - iv.Length];
            Array.Copy(encryptedData, iv.Length, cipherBytes, 0, cipherBytes.Length);

            using (var decryptor = aes.CreateDecryptor(derivedKey, iv))
            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                {
                    cs.Write(cipherBytes, 0, cipherBytes.Length);
                    cs.FlushFinalBlock();
                }

                byte[] decryptedBytes = ms.ToArray();
                return Encoding.UTF8.GetString(decryptedBytes);
            }
        }
    }

    // Saves the encrypted data, plain text, and secret key to a file
    static void SaveEncryptedDataToFile(string filePath, string plainText, string secretKey, string encryptedData)
    {
        try
        {
            using (StreamWriter writer = new StreamWriter(filePath))
            {
                writer.WriteLine("Plain Text: " + plainText);
                writer.WriteLine("Secret Key: " + secretKey);
                writer.WriteLine("Encrypted Data (Base64): " + encryptedData);
            }

            Console.WriteLine("Encrypted data and related information saved to file successfully.");
        }
        catch (Exception ex)
        {
            Console.WriteLine("An error occurred while saving the encrypted data to file: " + ex.Message);
        }
    }
}
