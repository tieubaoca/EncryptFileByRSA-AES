using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace RSAEncryptionFile
{
    class ViewModel : BaseViewModel
    {
        public ICommand GenerateCommand { get; set; }
        private string publicKey;
        private string privateKey;
        RSACryptoServiceProvider rsa;
        public Aes aes;
        public string PublicKey
        {
            get { return publicKey; }
            set { publicKey = value; OnPropertyChanged(); }
        }
        public string PrivateKey
        {
            get { return privateKey; }
            set { privateKey = value; OnPropertyChanged(); }
        }
        public byte[] DataToEncrypt { get; set; }
        public byte[] EncryptedData { get; set; }
        public ViewModel()
        {
            GenerateCommand = new RelayCommand<object>(p => { return true; }, p =>
            {

                //Import the RSA Key information. This only needs
                //toinclude the public key information.
                //RSA.ImportParameters(RSAKeyInfo);

                rsa = new RSACryptoServiceProvider(2048);
                PublicKey = rsa.ToXmlString(false);
                PrivateKey = rsa.ToXmlString(true);
                EncryptFile("pixel.jpg");
                //Encrypt the passed byte array and specify OAEP padding.  
                //OAEP padding is only available on Microsoft Windows XP or
                //later.  
                //EncryptedData = RSA.Encrypt(DataToEncrypt, true);

            });
        }
        private void EncryptFile(string infile)
        {

            aes = Aes.Create();
            ICryptoTransform transform = aes.CreateEncryptor();
            //ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            byte[] keyEncrypted = rsa.Encrypt(aes.Key, false);
            PublicKey = Convert.ToBase64String(keyEncrypted);
            byte[] LenK = new byte[4];
            byte[] LenIV = new byte[4];
            int lKey = keyEncrypted.Length;
            LenK = BitConverter.GetBytes(lKey);
            int lIV = aes.IV.Length;
            LenIV = BitConverter.GetBytes(lIV);

            int startFileName = infile.LastIndexOf("\\") + 1;
            // Change the file's extension to ".enc"
            //string outfile ="Output//" +  infile.Substring(startFileName, infile.LastIndexOf(".") - startFileName) + ".enc";
            string outfile = "Output//" + infile;
            
            using (FileStream outFs = new FileStream(outfile, FileMode.Create))
            {

                outFs.Write(LenK, 0, 4);
                outFs.Write(LenIV, 0, 4);
                outFs.Write(keyEncrypted, 0, lKey);
                outFs.Write(aes.IV, 0, lIV);

                // Now write the cipher text using
                // a CryptoStream for encrypting.
                using (CryptoStream outStreamEncrypted = new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                {

                    // By encrypting a chunk at
                    // a time, you can save memory
                    // and accommodate large files.
                    int count = 0;
                    int offset = 0;

                    // blockSizeBytes can be any arbitrary size.
                    int blockSizeBytes = aes.BlockSize / 8;
                    byte[] data = new byte[blockSizeBytes];
                    int bytesRead = 0;

                    using (FileStream inFs = new FileStream(infile, FileMode.Open))
                    {
                        do
                        {
                            count = inFs.Read(data, 0, blockSizeBytes);
                            offset += count;
                            outStreamEncrypted.Write(data, 0, count);
                            bytesRead += blockSizeBytes;
                        }
                        while (count > 0);
                        inFs.Close();
                    }
                    outStreamEncrypted.FlushFinalBlock();
                    outStreamEncrypted.Close();
                }
                outFs.Close();
            }
        }

    }
}
