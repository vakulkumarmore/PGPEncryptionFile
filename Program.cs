using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using PGPEncrypt;
using System.Configuration;
using System.IO;

namespace STOPFILES
{
    class Program
    {
        static void Main(string[] args)
        {   
            PGPEncryption pgp = new PGPEncryption();

            //string filePath = @"C:\form.doc";
            //string pathToSaveFile = @"C:\";
            //string publicKeyFile = @"C:\StopFiles\pecom-public-key.asc";
            //encryptedFileName = pgp.Encrypt(filePath, publicKeyFile, pathToSaveFile);


            string encryptedFileName = string.Empty;   
            string filePathfolder = ConfigurationManager.AppSettings["filePath"].ToString();  //filePath for Source from AppConfig
            string pathtoSaveFilePGP = ConfigurationManager.AppSettings["pathToSaveFile"].ToString(); //filePath to save PGP file from AppConfig
            string publicKeyFile = ConfigurationManager.AppSettings["publicKeyFile"].ToString(); //Public Key Provided by ACI
            string FileType = ConfigurationManager.AppSettings["FileType"].ToString(); //Determining file type from AppConfig

            DirectoryInfo d = new DirectoryInfo(filePathfolder);    
            FileInfo[] Files = d.GetFiles(FileType); //Getting Text files 

            foreach (FileInfo file in Files) //For Each file in the folder
            {
                filePathfolder = filePathfolder + file;
                encryptedFileName = pgp.Encrypt(filePathfolder, publicKeyFile, pathtoSaveFilePGP); //Encrypt the file and save to new folder location
                filePathfolder = ConfigurationManager.AppSettings["filePath"].ToString(); //reset the source file path to the folder
            }

        }
             

        }


    }

