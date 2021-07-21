using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using FolderBrowserDialog = System.Windows.Forms.FolderBrowserDialog;
using System.Windows.Input;
using System.Windows.Controls;
using System.Threading;

namespace RSAEncryptionFile
{
    class ViewModel : BaseViewModel
    {
        public ICommand GenerateCommand { get; set; }
        public ICommand SaveCommand { get; set; }
        public ICommand ChooseOutput { get; set; }
        public ICommand ImportFileCommand { get; set; }
        public ICommand EncryptCommand { get; set; }
        public ICommand ImportEnKeyCommand { get; set; }
        public ICommand ImportDecryptKeyCommand { get; set; }
        public ICommand ImportEnFileCommand { get; set; }
        public ICommand DecryptFileCommand { get; set; }
        private string decryptKey;

        public string DecryptKey
        {
            get { return decryptKey; }
            set { decryptKey = value;OnPropertyChanged(); }
        }

        private string publicKey;
        private string privateKey;
        private string output;
        private string encryptKey;
        private string inputFile;
        private string inputEnFile;

        public string InputEnFile
        {
            get { return inputEnFile; }
            set { inputEnFile = value; OnPropertyChanged(); }
        }


        public string EncryptKey
        {
            get { return encryptKey; }
            set { encryptKey = value;OnPropertyChanged(); }
        }

        RSACryptoServiceProvider decrsa { get; set; } = new RSACryptoServiceProvider();
        RSACryptoServiceProvider rsa { get; set; }
        public Aes decaes { get; set; }
        public Aes aes { get; set; }
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
        public string Output
        {
            get { return output; }
            set { output = value; OnPropertyChanged(); }
        }
        public ICryptoTransform transform { get; set; }
        public byte[] keyEncrypted { get; set; }
        public string InputFile { get=>inputFile; set{ inputFile = value;OnPropertyChanged(); } }
        public byte[] DataToEncrypt { get; set; }
        public byte[] EncryptedData { get; set; }
        public ViewModel()
        {
            GenerateCommand = new RelayCommand<object>(p => { return true; }, p =>
            {
                Button Btn = p as Button;
                Btn.Content = "Pendding...";
                ThreadPool.QueueUserWorkItem((pp) => 
                { 
                    GenerateKeys(); 
                    Button btn = p as Button; 
                    btn.Dispatcher.Invoke(()=>btn.Content = "Generate Keys"); 
                },Btn);
                

            });
            SaveCommand = new RelayCommand<string>(p => { return true; }, p =>
            {
                SaveFileDialog fileDialog = new SaveFileDialog();
                fileDialog.Filter = "XML File| *.xml";
                fileDialog.Title = "Save a xml File";
                if (fileDialog.ShowDialog()==true)
                {
                    if (fileDialog.FileName != null)
                    {
                        File.WriteAllText(fileDialog.FileName, p);

                    }
                }
            });
            ChooseOutput = new RelayCommand<object>(p => true, p =>
            {
                FolderBrowserDialog folderBrowserDialog = new FolderBrowserDialog();
                if (folderBrowserDialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                {
                    if (folderBrowserDialog.SelectedPath != null)
                    {
                        Output = folderBrowserDialog.SelectedPath;
                    }
                }
            });
            ImportFileCommand = new RelayCommand<object>(p => true, p =>
            {
                OpenFileDialog fileDialog = new OpenFileDialog();
                if (fileDialog.ShowDialog() == true)
                {
                    if (fileDialog.FileName != null)
                    {
                        InputFile = fileDialog.FileName;
                    }
                }
            });
            EncryptCommand = new RelayCommand<Button>(p =>
            {
                return string.IsNullOrWhiteSpace(InputFile) || rsa==null ? false : true;
            }, p =>
            {
                p.Content = "Pendding...";
                ThreadPool.QueueUserWorkItem(pp => {
                    Button btn = pp as Button;
                    EncryptFile(InputFile, Output);
                    MessageBox.Show("Done");
                    btn.Dispatcher.Invoke(() => { btn.Content = "Encrypt File"; });
                },p);
                
            });
            ImportEnKeyCommand = new RelayCommand<Button>(p => true, p =>
            {
                try
                {
                    OpenFileDialog openFileDialog = new OpenFileDialog()
                    {
                        Filter="Public key or Private key, XML file|*.xml"
                    };
                    
                    if (openFileDialog.ShowDialog() == true)
                    {
                        if (openFileDialog.FileName != null)
                        {
                            CspParameters cspp = new CspParameters();
                            cspp.KeyContainerName = "TieuBaoCa";
                            rsa = new RSACryptoServiceProvider(cspp);
                            rsa.FromXmlString(File.ReadAllText(openFileDialog.FileName));
                            PublicKey = rsa.ToXmlString(false);
                            aes = Aes.Create();
                            transform = aes.CreateEncryptor();
                            keyEncrypted = rsa.Encrypt(aes.Key, false);
                            EncryptKey = Convert.ToBase64String(keyEncrypted);
                            try { PrivateKey = rsa.ToXmlString(true); }catch(Exception) { }
                        }
                    }
                }
                catch (Exception ex) { MessageBox.Show(ex.ToString()); }
            });
            ImportDecryptKeyCommand = new RelayCommand<object>(p => true, p =>
               {
                   OpenFileDialog openFileDialog = new OpenFileDialog() {
                       Filter = "Encrypt Key Pair XML File|*.xml"
                   };
                   if (openFileDialog.ShowDialog() == true)
                   {
                       if (openFileDialog.FileName != null)
                       {
                           DecryptKey = openFileDialog.FileName;
                           decrsa.FromXmlString(File.ReadAllText(openFileDialog.FileName));
                       }
                   }
               });
            ImportEnFileCommand = new RelayCommand<object>(p => true, p =>
            {
                OpenFileDialog openFileDialog = new OpenFileDialog();
                if (openFileDialog.ShowDialog() == true)
                {
                    if (openFileDialog.FileName != null)
                    {
                        InputEnFile = openFileDialog.FileName;
                    }
                }
            });

            DecryptFileCommand = new RelayCommand<Button>(p => string.IsNullOrWhiteSpace(InputEnFile) || decrsa == null ? false : true,
                p =>
                {
                    p.Content = "Pendding...";
                    ThreadPool.QueueUserWorkItem(pp => {
                        DecryptFile(InputEnFile);
                        Button btn = pp as Button;
                        btn.Dispatcher.Invoke(() =>
                        {
                            btn.Content = "Decrypt File";
                        });
                        MessageBox.Show("Done");
                    }, p);
                    
                });
        }

        private void GenerateKeys()
        {
            //Import the RSA Key information. This only needs
            //toinclude the public key information.
            //RSA.ImportParameters(RSAKeyInfo);

            rsa = new RSACryptoServiceProvider(2048);
            PublicKey = rsa.ToXmlString(false);
            PrivateKey = rsa.ToXmlString(true);
            aes = Aes.Create();
            transform = aes.CreateEncryptor();
            //ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            keyEncrypted = rsa.Encrypt(aes.Key, false);
            EncryptKey = Convert.ToBase64String(keyEncrypted);
            //Encrypt the passed byte array and specify OAEP padding.  
            //OAEP padding is only available on Microsoft Windows XP or
            //later.  
            //EncryptedData = RSA.Encrypt(DataToEncrypt, true);
        }

        private void EncryptFile(string infile,string outfile)
        {


            byte[] LenK = new byte[4];
            byte[] LenIV = new byte[4];
            int lKey = keyEncrypted.Length;
            LenK = BitConverter.GetBytes(lKey);
            int lIV = aes.IV.Length;
            LenIV = BitConverter.GetBytes(lIV);

            int endFileName = infile.LastIndexOf(".");
            
            // Change the file's extension to ".enc"
            //outfile = outfile +  infile.Substring(startFileName, infile.LastIndexOf(".") - startFileName) + ".enc";
            outfile = infile.Insert(endFileName,"Encrypted");

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
        private void DecryptFile(string EncryptedFile)
        {

            // Create instance of Aes for
            // symetric decryption of the data.
            decaes = Aes.Create();

            // Create byte arrays to get the length of
            // the encrypted key and IV.
            // These values were stored as 4 bytes each
            // at the beginning of the encrypted package.
            byte[] LenK = new byte[4];
            byte[] LenIV = new byte[4];
            int endFilename = EncryptedFile.LastIndexOf(".");
            // Construct the file name for the decrypted file.
            string outFile = EncryptedFile.Insert(endFilename,"Decrypted");

            // Use FileStream objects to read the encrypted
            // file (inFs) and save the decrypted file (outFs).
            using (FileStream inFs = new FileStream(EncryptedFile, FileMode.Open))
            {

                inFs.Seek(0, SeekOrigin.Begin);
                inFs.Seek(0, SeekOrigin.Begin);
                inFs.Read(LenK, 0, 3);
                inFs.Seek(4, SeekOrigin.Begin);
                inFs.Read(LenIV, 0, 3);

                // Convert the lengths to integer values.
                int lenK = BitConverter.ToInt32(LenK, 0);
                int lenIV = BitConverter.ToInt32(LenIV, 0);

                // Determine the start postition of
                // the ciphter text (startC)
                // and its length(lenC).
                int startC = lenK + lenIV + 8;
                int lenC = (int)inFs.Length - startC;

                // Create the byte arrays for
                // the encrypted Aes key,
                // the IV, and the cipher text.
                byte[] KeyEncrypted = new byte[lenK];
                byte[] IV = new byte[lenIV];

                // Extract the key and IV
                // starting from index 8
                // after the length values.
                inFs.Seek(8, SeekOrigin.Begin);
                inFs.Read(KeyEncrypted, 0, lenK);
                inFs.Seek(8 + lenK, SeekOrigin.Begin);
                inFs.Read(IV, 0, lenIV);
                // Use RSACryptoServiceProvider
                // to decrypt the AES key.
                byte[] KeyDecrypted;
                try
                {
                    KeyDecrypted = decrsa.Decrypt(KeyEncrypted, false);
                }
                catch(CryptographicException)
                {
                    MessageBox.Show("Please Import A Key Pair Include Puclic Key & Private Key");
                    return;
                }
                // Decrypt the key.
                ICryptoTransform dectransform = decaes.CreateDecryptor(KeyDecrypted, IV);

                // Decrypt the cipher text from
                // from the FileSteam of the encrypted
                // file (inFs) into the FileStream
                // for the decrypted file (outFs).
                using (FileStream outFs = new FileStream(outFile, FileMode.Create))
                {

                    int count = 0;
                    int offset = 0;

                    // blockSizeBytes can be any arbitrary size.
                    int blockSizeBytes = decaes.BlockSize / 8;
                    byte[] data = new byte[blockSizeBytes];

                    // By decrypting a chunk a time,
                    // you can save memory and
                    // accommodate large files.

                    // Start at the beginning
                    // of the cipher text.
                    inFs.Seek(startC, SeekOrigin.Begin);
                    using (CryptoStream outStreamDecrypted = new CryptoStream(outFs, dectransform, CryptoStreamMode.Write))
                    {
                        do
                        {
                            count = inFs.Read(data, 0, blockSizeBytes);
                            offset += count;
                            outStreamDecrypted.Write(data, 0, count);
                        }
                        while (count > 0);

                        outStreamDecrypted.FlushFinalBlock();
                        outStreamDecrypted.Close();
                    }
                    outFs.Close();
                }
                inFs.Close();
            }
        }

    }
}
