using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using System.Security.Cryptography;
using System.Security.AccessControl;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Security;

namespace PGPEncrypt
{
    /// <summary>
    /// Method to encrypt a file using a public key file
    /// </summary>
    /// <param name=”filePath”>The path of the file to be encrypted</param>
    /// <param name=”publicKeyFile”>The path of the public key file</param>
    /// <param name=”pathToSaveFile”>The path where encrypted file will be saved</param>
    /// 

    public class PGPEncryption
    {

       
        public string Encrypt(string filePath, string publicKeyFile, string pathToSaveFile)
        {
            Stream keyIn, fos;

            keyIn = File.OpenRead(publicKeyFile);

            string[] fileSplit = filePath.Split('\\');

            string fileName = fileSplit[fileSplit.Length - 1];

            fos = File.Create(pathToSaveFile + fileName + ".pgp");

            EncryptFile(fos, filePath, ReadPublicKey(keyIn), true, true);

            keyIn.Close();

            fos.Close();

            return fileName + ".pgp";

        }

        private static void EncryptFile(Stream outputStream, string fileName, PgpPublicKey encKey, bool armor, bool withIntegrityCheck)
        {

            if (armor)
            {

                outputStream = new ArmoredOutputStream(outputStream);

            }

            try
            {

                MemoryStream bOut = new MemoryStream();
                PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(
                CompressionAlgorithmTag.Zip);
                PgpUtilities.WriteFileToLiteralData(comData.Open(bOut),PgpLiteralData.Binary,new FileInfo(fileName));
                comData.Close();
                PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(
                SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());
                cPk.AddMethod(encKey);
                byte[] bytes = bOut.ToArray();
                Stream cOut = cPk.Open(outputStream, bytes.Length);
                cOut.Write(bytes, 0, bytes.Length);
                cOut.Close();
                if (armor)
                {

                    outputStream.Close();

                }


            }

            catch (PgpException e)
            {

                Console.Error.WriteLine(e);
                Exception underlyingException = e.InnerException;
                if (underlyingException != null)
                {

                    Console.Error.WriteLine(underlyingException.Message);
                    Console.Error.WriteLine(underlyingException.StackTrace);

                }


            }


        }

        private static PgpPublicKey ReadPublicKey(Stream inputStream)
        {

            inputStream = PgpUtilities.GetDecoderStream(inputStream);
            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);
            //
            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            //
            //
            // iterate through the key rings.
            //
            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
            {

                foreach (PgpPublicKey k in kRing.GetPublicKeys())
                {

                    if (k.IsEncryptionKey)
                    {

                        return k;

                    }


                }


            }

            throw new ArgumentException("Can't find encryption key in key ring.");

        }
    }

   
    
}
