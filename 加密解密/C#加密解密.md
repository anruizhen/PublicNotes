# C#.NET中对称和非对称加密、解密方法汇总

摘自[C#.NET中对称和非对称加密、解密方法汇总](https://www.cnblogs.com/lvxiangjack/p/10426625.html)

.NET为封装了常用的加密算法，例如：`MD5`,`DES`,`RSA`等。有可逆加密，也有非可逆加密;有对称加密，也有非对称加密。加密、解密一般会用在软件的注册码，系统密码，通讯中。

## 1-不可逆加密

不可逆加密一般不会涉及到解密。也就是是加密之后的密文不能还原成原来的明文。这种算法一般用于生成自信摘要，确保数据的完整性及防篡改。

1. 使用`FormsAuthentication`类加密

```csharp {.line.numers}
using System.Web.Security;
    
namespace EncyptDemo
{
    public class WebEncryptor
    {
        /// <summary>
        /// SHA1加密字符串
        /// </summary>
        /// <param name="source">源字符串</param>
        /// <returns>加密后的字符串</returns>
        public string SHA1(string source)
        {
            return FormsAuthentication.HashPasswordForStoringInConfigFile(source, "SHA1");
        }
    
        /// <summary>
        /// MD5加密字符串
        /// </summary>
        /// <param name="source">源字符串</param>
        /// <returns>加密后的字符串</returns>
        public string MD5(string source)
        {
            return FormsAuthentication.HashPasswordForStoringInConfigFile(source, "MD5"); ;
        }
    
    }
}
```

2. 使用`MD5CryptoServiceProvider`类生成`MD5`字符串

```csharp
using System;
using System.Security.Cryptography;
using System.Text;
    
namespace EncyptDemo
{
    public class MD5Helper
    {
        public string GetMD5_32(string s, string _input_charset = "utf8")
        {
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] t = md5.ComputeHash(Encoding.GetEncoding(_input_charset).GetBytes(s));
            StringBuilder sb = new StringBuilder(32);
            for (int i = 0; i < t.Length; i++)
            {
                sb.Append(t[i].ToString("x").PadLeft(2, '0'));
            }
            return sb.ToString();
        }
    
        //16位加密
        public static string GetMd5_16(string s)
        {
            MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
            string t2 = BitConverter.ToString(md5.ComputeHash(UTF8Encoding.Default.GetBytes(s)), 4, 8);
            t2 = t2.Replace("-", "");
            return t2;
        }
    
    }
}
```

## 2-可逆加密

可逆加密，这种算法加密之后的密码文可以解密成原来的明文。比如通讯的时候，数据的发送方和接收方约定好加密和解密的key，发送放把原始数据加密之后开始发送，接收放收到数据之后开始解密，把密文原来成明文。

可逆加密又分为对称加密和非对称加密。所谓对称加密就是加密和解密的算法一样，也就是用来加密的key和解密的key是完全一样的。而非对称加密加密的key和解密的key是不一样的，加密是用公钥，解密是用私钥。

### 2.1- 对称加密

对称加密算法是应用较早的加密算法，技术成熟。在对称加密算法中，数据发信方将明文（原始数据）和加密密钥一起经过特殊加密算法处理后，使其变成复杂的加密密文发送出去。收信方收到密文后，若想解读原文，则需要使用加密用过的密钥及相同算法的逆算法对密文进行解密，才能使其恢复成可读明文。

在对称加密算法中，使用的密钥只有一个，发收信双方都使用这个密钥对数据进行加密和解密，这就要求解密方事先必须知道加密密钥。对称加密算法的特点是算法公开、计算量小、加密速度快、加密效率高。不足之处是，交易双方都使用同样钥匙，安全性得不到保证。此外，每对用户每次使用对称加密算法时，都需要使用其他人不知道的惟一钥匙，这会使得发收信双方所拥有的钥匙数量成几何级数增长，密钥管理成为用户的负担。对称加密算法在分布式网络系统上使用较为困难，主要是因为密钥管理困难，使用成本较高。在计算机专网系统中广泛使用的对称加密算法有DES、IDEA和AES。

1. `基本`示例

```csharp
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
    
namespace EncyptDemo
{
    public class SymmetryEncrypt
    {
        private SymmetricAlgorithm mobjCryptoService;
        private string Key;
        /// <summary>  
        /// 对称加密类的构造函数  
        /// </summary>  
        public SymmetryEncrypt()
        {
            mobjCryptoService = new RijndaelManaged();
            Key = "Guz(%&hj7x89H$yuBI0456FtmaT5&fvHUFCy76*h%(HilJ$lhj!y6&(*jkP87jH7";
        }
        /// <summary>  
        /// 获得密钥  
        /// </summary>  
        /// <returns>密钥</returns>  
        private byte[] GetLegalKey()
        {
            string sTemp = Key;
            mobjCryptoService.GenerateKey();
            byte[] bytTemp = mobjCryptoService.Key;
            int KeyLength = bytTemp.Length;
            if (sTemp.Length > KeyLength)
                sTemp = sTemp.Substring(0, KeyLength);
            else if (sTemp.Length < KeyLength)
                sTemp = sTemp.PadRight(KeyLength, ' ');
            return ASCIIEncoding.ASCII.GetBytes(sTemp);
        }
        /// <summary>  
        /// 获得初始向量IV  
        /// </summary>  
        /// <returns>初试向量IV</returns>  
        private byte[] GetLegalIV()
        {
            string sTemp = "E4ghj*Ghg7!rNIfb&95GUY86GfghUb#er57HBh(u%g6HJ($jhWk7&!hg4ui%$hjk";
            mobjCryptoService.GenerateIV();
            byte[] bytTemp = mobjCryptoService.IV;
            int IVLength = bytTemp.Length;
            if (sTemp.Length > IVLength)
                sTemp = sTemp.Substring(0, IVLength);
            else if (sTemp.Length < IVLength)
                sTemp = sTemp.PadRight(IVLength, ' ');
            return ASCIIEncoding.ASCII.GetBytes(sTemp);
        }
        /// <summary>  
        /// 加密方法  
        /// </summary>  
        /// <param name="Source">待加密的串</param>  
        /// <returns>经过加密的串</returns>  
        public string Encrypto(string Source)
        {
            byte[] bytIn = UTF8Encoding.UTF8.GetBytes(Source);
            MemoryStream ms = new MemoryStream();
            mobjCryptoService.Key = GetLegalKey();
            mobjCryptoService.IV = GetLegalIV();
            ICryptoTransform encrypto = mobjCryptoService.CreateEncryptor();
            CryptoStream cs = new CryptoStream(ms, encrypto, CryptoStreamMode.Write);
            cs.Write(bytIn, 0, bytIn.Length);
            cs.FlushFinalBlock();
            ms.Close();
            byte[] bytOut = ms.ToArray();
            return Convert.ToBase64String(bytOut);
        }
        /// <summary>  
        /// 解密方法  
        /// </summary>  
        /// <param name="Source">待解密的串</param>  
        /// <returns>经过解密的串</returns>  
        public string Decrypto(string Source)
        {
            byte[] bytIn = Convert.FromBase64String(Source);
            MemoryStream ms = new MemoryStream(bytIn, 0, bytIn.Length);
            mobjCryptoService.Key = GetLegalKey();
            mobjCryptoService.IV = GetLegalIV();
            ICryptoTransform encrypto = mobjCryptoService.CreateDecryptor();
            CryptoStream cs = new CryptoStream(ms, encrypto, CryptoStreamMode.Read);
            StreamReader sr = new StreamReader(cs);
            return sr.ReadToEnd();
        }
    
    }
}
```

2. `DES`加密

在对称加密算法中比较著名和常用的就是大名鼎鼎的DES加密算法，它安全性比较高的一种算法，目前只有一种方法可以破解该算法，那就是穷举法。

```csharp
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncyptDemo
{
    public class DESHeper
    {
        //默认密钥向量
        private static byte[] Keys = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };
        /// <summary>
        /// DES加密字符串
        /// </summary>
        /// <param name="encryptString">待加密的字符串</param>
        /// <param name="encryptKey">加密密钥,要求为8位</param>
        /// <returns>加密成功返回加密后的字符串，失败返回源串</returns>
        public static string EncryptDES(string encryptString, string encryptKey)
        {
            try
            {
                byte[] rgbKey = Encoding.UTF8.GetBytes(encryptKey.Substring(0, 8));
                byte[] rgbIV = Keys;
                byte[] inputByteArray = Encoding.UTF8.GetBytes(encryptString);
                DESCryptoServiceProvider dCSP = new DESCryptoServiceProvider();
                MemoryStream mStream = new MemoryStream();
                CryptoStream cStream = new CryptoStream(mStream, dCSP.CreateEncryptor(rgbKey, rgbIV), CryptoStreamMode.Write);
                cStream.Write(inputByteArray, 0, inputByteArray.Length);
                cStream.FlushFinalBlock();
                return Convert.ToBase64String(mStream.ToArray());
            }
            catch
            {
                return encryptString;
            }
        }

        /// <summary>
        /// DES解密字符串
        /// </summary>
        /// <param name="decryptString">待解密的字符串</param>
        /// <param name="decryptKey">解密密钥,要求为8位,和加密密钥相同</param>
        /// <returns>解密成功返回解密后的字符串，失败返源串</returns>
        public static string DecryptDES(string decryptString, string decryptKey)
        {
            try
            {
                byte[] rgbKey = Encoding.UTF8.GetBytes(decryptKey);
                byte[] rgbIV = Keys;
                byte[] inputByteArray = Convert.FromBase64String(decryptString);
                DESCryptoServiceProvider DCSP = new DESCryptoServiceProvider();
                MemoryStream mStream = new MemoryStream();
                CryptoStream cStream = new CryptoStream(mStream, DCSP.CreateDecryptor(rgbKey, rgbIV), CryptoStreamMode.Write);
                cStream.Write(inputByteArray, 0, inputByteArray.Length);
                cStream.FlushFinalBlock();
                return Encoding.UTF8.GetString(mStream.ToArray());
            }
            catch
            {
                return decryptString;
            }
        }

        /// <summary>
        /// DES加密方法
        /// </summary>
        /// <param name="strPlain">明文</param>
        /// <param name="strDESKey">密钥</param>
        /// <param name="strDESIV">向量</param>
        /// <returns>密文</returns>
        public string DESEncrypt(string strPlain, string strDESKey, string strDESIV)
        {
            //把密钥转换成字节数组
            byte[] bytesDESKey = ASCIIEncoding.ASCII.GetBytes(strDESKey);
            //把向量转换成字节数组
            byte[] bytesDESIV = ASCIIEncoding.ASCII.GetBytes(strDESIV);
            //声明1个新的DES对象
            DESCryptoServiceProvider desEncrypt = new DESCryptoServiceProvider();
            //开辟一块内存流
            MemoryStream msEncrypt = new MemoryStream();
            //把内存流对象包装成加密流对象
            CryptoStream csEncrypt = new CryptoStream(msEncrypt, desEncrypt.CreateEncryptor(bytesDESKey, bytesDESIV), CryptoStreamMode.Write);
            //把加密流对象包装成写入流对象
            StreamWriter swEncrypt = new StreamWriter(csEncrypt);
            //写入流对象写入明文
            swEncrypt.WriteLine(strPlain);
            //写入流关闭
            swEncrypt.Close();
            //加密流关闭
            csEncrypt.Close();
            //把内存流转换成字节数组，内存流现在已经是密文了
            byte[] bytesCipher = msEncrypt.ToArray();
            //内存流关闭
            msEncrypt.Close();
            //把密文字节数组转换为字符串，并返回
            return UnicodeEncoding.Unicode.GetString(bytesCipher);
        }

        /// <summary>
        /// DES解密方法
        /// </summary>
        /// <param name="strCipher">密文</param>
        /// <param name="strDESKey">密钥</param>
        /// <param name="strDESIV">向量</param>
        /// <returns>明文</returns>
        public string DESDecrypt(string strCipher, string strDESKey, string strDESIV)
        {
            //把密钥转换成字节数组
            byte[] bytesDESKey = ASCIIEncoding.ASCII.GetBytes(strDESKey);
            //把向量转换成字节数组
            byte[] bytesDESIV = ASCIIEncoding.ASCII.GetBytes(strDESIV);
            //把密文转换成字节数组
            byte[] bytesCipher = UnicodeEncoding.Unicode.GetBytes(strCipher);
            //声明1个新的DES对象
            DESCryptoServiceProvider desDecrypt = new DESCryptoServiceProvider();
            //开辟一块内存流，并存放密文字节数组
            MemoryStream msDecrypt = new MemoryStream(bytesCipher);
            //把内存流对象包装成解密流对象
            CryptoStream csDecrypt = new CryptoStream(msDecrypt, desDecrypt.CreateDecryptor(bytesDESKey, bytesDESIV), CryptoStreamMode.Read);
            //把解密流对象包装成读出流对象
            StreamReader srDecrypt = new StreamReader(csDecrypt);
            //明文=读出流的读出内容
            string strPlainText = srDecrypt.ReadLine();
            //读出流关闭
            srDecrypt.Close();
            //解密流关闭
            csDecrypt.Close();
            //内存流关闭
            msDecrypt.Close();
            //返回明文
            return strPlainText;
        }

    }
}
```

3. `DES`加密文件

```csharp
using System;
using System.IO;
using System.Security.Cryptography;

namespace EncyptDemo
{
    public class FileEncrypt
    {
        private static void EncryptData(String pathInput, String pathOutput, byte[] desKey, byte[] desIV)
        {
            //Create the file streams to handle the input and output files.
            FileStream fin = new FileStream(pathInput, FileMode.Open, FileAccess.Read);
            FileStream fout = new FileStream(pathOutput, FileMode.OpenOrCreate, FileAccess.Write);
            fout.SetLength(0);

            //Create variables to help with read and write.
            byte[] bin = new byte[100]; //This is intermediate storage for the encryption.
            long rdlen = 0;              //This is the total number of bytes written.
            long totlen = fin.Length;    //This is the total length of the input file.
            int len;                     //This is the number of bytes to be written at a time.

            DES des = new DESCryptoServiceProvider();
            CryptoStream encStream = new CryptoStream(fout, des.CreateEncryptor(desKey, desIV), CryptoStreamMode.Write);

            //Read from the input file, then encrypt and write to the output file.
            while (rdlen < totlen)
            {
                len = fin.Read(bin, 0, 100);
                encStream.Write(bin, 0, len);
                rdlen = rdlen + len;
            }

            encStream.Close();
            fout.Close();
            fin.Close();
        }

        //解密文件
        private static void DecryptData(String pathInput, String pathOutput, byte[] desKey, byte[] desIV)
        {
            //Create the file streams to handle the input and output files.
            FileStream fin = new FileStream(pathInput, FileMode.Open, FileAccess.Read);
            FileStream fout = new FileStream(pathOutput, FileMode.OpenOrCreate, FileAccess.Write);
            fout.SetLength(0);

            //Create variables to help with read and write.
            byte[] bin = new byte[100]; //This is intermediate storage for the encryption.
            long rdlen = 0;              //This is the total number of bytes written.
            long totlen = fin.Length;    //This is the total length of the input file.
            int len;                     //This is the number of bytes to be written at a time.

            DES des = new DESCryptoServiceProvider();
            CryptoStream encStream = new CryptoStream(fout, des.CreateDecryptor(desKey, desIV), CryptoStreamMode.Write);

            //Read from the input file, then encrypt and write to the output file.
            while (rdlen < totlen)
            {
                len = fin.Read(bin, 0, 100);
                encStream.Write(bin, 0, len);
                rdlen = rdlen + len;
            }

            encStream.Close();
            fout.Close();
            fin.Close();
        }
    }
}
```

### 2.2- 非对称加密

不对称加密算法使用两把完全不同但又是完全匹配的一对钥匙—公钥和私钥。在使用不对称加密算法加密文件时，只有使用匹配的一对公钥和私钥，才能完成对明文的加密和解密过程。加密明文时采用公钥加密，解密密文时使用私钥才能完成，而且发信方（加密者）知道收信方的公钥，只有收信方（解密者）才是唯一知道自己私钥的人。不对称加密算法的基本原理是，如果发信方想发送只有收信方才能解读的加密信息，发信方必须首先知道收信方的公钥，然后利用收信方的公钥来加密原文；收信方收到加密密文后，使用自己的私钥才能解密密文。显然，采用不对称加密算法，收发信双方在通信之前，收信方必须将自己早已随机生成的公钥送给发信方，而自己保留私钥。由于不对称算法拥有两个密钥，因而特别适用于分布式系统中的数据加密。

广泛应用的不对称加密算法有RSA算法和美国国家标准局提出的`DSA`。以不对称加密算法为基础的加密技术应用非常广泛。尤其是在`Linux`系统下会经常用到这种非对称加密。反正你只需要记住一点有公钥和私钥对的就是非对称加密。

`C#`中的怎么实现RSA非对称加密。

`首先`，我们要生成一个公钥和私钥对。

```csharp
using System.IO;
using System.Security.Cryptography;
    
namespace ConsoleApplication1
{
    class Program
    {
        static void Main(string[] args)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            using (StreamWriter writer = new StreamWriter("PrivateKey.xml",false))  //这个文件要保密...
            {
                writer.WriteLine(rsa.ToXmlString(true));
            }
            using (StreamWriter writer = new StreamWriter("PublicKey.xml",false))
            {
                writer.WriteLine(rsa.ToXmlString(false));
    
            }
        }
    }
}
```

运行上面的控制台程序会在程序目录下生成配对的公钥`PublicKey.xml`和私钥文件`PrivateKey.xml`。

`接着`写一个RSA加密解密类

```csharp
using System;
using System.Collections.Generic;
using System.linq;
using System.Text;
using System.Security.Cryptography;
    
namespace ClassLibrary1
{
    public class RSAHelper
    {
        static string PublicKey = @"<RSAKeyValue><Modulus>nwbjN1znmyL2KyOIrRy/PbWZpTi+oekJIoGNc6jHCl0JNZLFHNs70fyf7y44BH8L8MBkSm5sSwCZfLm5nAsDNOmuEV5Uab5DuWYSE4R2Z3NkKexJJ4bnmXEZYXPMzTbXIpyvU2y9YVrz1BjjRPeHsb6daVdrBgjs4+2b/ok9myM=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
        static string PrivateKey = @"<RSAKeyValue><Modulus>nwbjN1znmyL2KyOIrRy/PbWZpTi+oekJIoGNc6jHCl0JNZLFHNs70fyf7y44BH8L8MBkSm5sSwCZfLm5nAsDNOmuEV5Uab5DuWYSE4R2Z3NkKexJJ4bnmXEZYXPMzTbXIpyvU2y9YVrz1BjjRPeHsb6daVdrBgjs4+2b/ok9myM=</Modulus><Exponent>AQAB</Exponent><P>2PfagXD2zKzUGLkAXpC+04u0xvESpO1PbTUOGA2m8auviEMNz8VempJ/reOlJjEO2q2nrUsbtqKd0m96Cxz0Fw==</P><Q>u6Kiit1XhIgRD9jQnQh36y28LOmku2Gqn9KownMSVGhWzkkHQPw77A2h1OirQiKe6aOIO/yxdwTI/9Ds4Kwc1Q==</Q><DP>GfwtPj1yQXcde8yEX88EG7/qqbzrl7cYQSMOihDwgpcmUbJ+L/kaaHbNNd1CxT0w4z3TDC0np4r4TeCuBDC2hw==</DP><DQ>hl8I0jOC2klrFpMpilunLUeaa/uCWiKuQzhkXKR1qvbxu1b3F+XKr9hvXX6mLn2GmkDfbj4fhOFrZC/lg1weZQ==</DQ><InverseQ>P1y+6el2+1LsdwL14hYCILvsTKGokGSKD35N7HakLmHNjXiU05hN1cnXMsGIZGg+pNHmz/yuPmgNLJoNZCQiCg==</InverseQ><D>D27DriO99jg2W4lfQi2AAaUV/Aq9tUjAMjEQYSEH7+GHe0N7DYnZDE/P1Y5OsWEC76I8GV0N9Vlhi9EaSiJndRvUgphTL2YuAjrVr59Il+lwh/LUBN46AX3cmQm3cFf1F1FXKj4S+QCx/qrCH4mmKpynuQsPL/1XiQSWpugI30E=</D></RSAKeyValue>";
        static RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(1024);
    
        public static byte[] EncryptData(byte[] data)
        {
    
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(1024);
    
            //将公钥导入到RSA对象中，准备加密；
            rsa.FromXmlString(PublicKey);
    
            //对数据data进行加密，并返回加密结果；
            //第二个参数用来选择Padding的格式
            byte[] buffer = rsa.Encrypt(data, false);
            return buffer;
        }
    
        public static byte[] DecryptData(byte[] data)
        {
    
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(1024);
    
            //将私钥导入RSA中，准备解密；
            rsa.FromXmlString(PrivateKey);
    
            //对数据进行解密，并返回解密结果；
            return rsa.Decrypt(data, false);
    
        }
            
    }
}
```

上面的`PublicKey`和`PrivateKey`非别是文件`PublicKey.xml`和`PrivateKey.xml`里面的内容。

**测试** `RSAHelper`的方法：

```csharp
[TestMethod()]
public void DecryptDataTest()
{
    byte[] data = System.Text.ASCIIEncoding.ASCII.GetBytes("Hello");
    byte[] data2 = RSAHelper.EncryptData(data);
    byte[] actual;
    actual = RSAHelper.DecryptData(data2);
    var a = System.Text.ASCIIEncoding.ASCII.GetString(actual);
    Assert.AreEqual("Hello", a);
}
```

可以看到上面通过`EncryptData`加密的数据能够通过`DecryptData`解密成原来的明文（Hello），而这个加密和解密用是不同的密钥。
