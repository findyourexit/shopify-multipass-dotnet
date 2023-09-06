using System.Security.Cryptography;
using System.Text;

namespace ShopifyMultipass;

public sealed class ShopifyMultipass
{
    private readonly string _secret;
    private readonly string _domain;

    public ShopifyMultipass(string secret, string domain)
    {
        if (string.IsNullOrEmpty(secret))
            throw new ArgumentNullException(nameof(secret));

        if (string.IsNullOrEmpty(domain))
            throw new ArgumentNullException(nameof(domain), "Please specify the shopify domain.");

        _secret = secret;
        _domain = domain;
    }

    public string Process(string customerJson)
    {
        if (string.IsNullOrEmpty(customerJson))
            throw new ArgumentNullException("input", "Customer object cannot be null.");
        
        var theHash = GenerateSHA256();

        var encryptionKeyArraySegment = new ArraySegment<byte>(theHash, 0, 16);
        var signatureKeyArraySegment = new ArraySegment<byte>(theHash, 16, 16);

        var encryptionKey = encryptionKeyArraySegment.ToArray();
        var signatureKey = signatureKeyArraySegment.ToArray();

        //generate random 16 bytes for Init Vactor
        var iv = new byte[16];
        new RNGCryptoServiceProvider().GetBytes(iv);

        //Generate Cipher using AES-128-CBC algo and concat Init Vector with this.
        var cipherData = EncryptStringToBytes(customerJson, encryptionKey, iv);
        var cipher = Combine(iv, cipherData);

        //Generate signature of Cipher
        HMACSHA256 hasher = new HMACSHA256(signatureKey);
        byte[] sing = hasher.ComputeHash(cipher);

        //append signature to cipher and convert it to URL safe base64 string
        var token = Convert.ToBase64String(Combine(cipher, sing)).Replace("+", "-").Replace("/", "_");

        //_log.InfoFormat("Multipass token => {0}", token);

        var redirectUrl = GetMultipassRedirectUrl(token);

        return redirectUrl;
    }

    /// <summary>
    /// Convert your data to multipass token and get redirect url for shopify mutipass
    /// </summary>
    /// <param name="token"></param>
    /// <returns></returns>
    private string GetMultipassRedirectUrl(string token)
    {
        //build redirect url
        return $"https://{_domain}/account/login/multipass/{token}";
    }

    public string SendToken(string token)
    {
        var url = GetMultipassRedirectUrl(token);

        var httpClient = new HttpClient();
        var response = httpClient.GetStringAsync(url).Result;
        
        return response;
    }

    private byte[] GenerateSHA256()
    {
        var theHash = SHA256.HashData(Encoding.UTF8.GetBytes(_secret));  
        return theHash;
    }


    private static byte[] EncryptStringToBytes(string plainText, byte[] key, byte[] iv)
    {
        // Check arguments.
        if (plainText is not { Length: > 0 })
            throw new ArgumentNullException(nameof(plainText));
        if (key is not { Length: > 0 })
            throw new ArgumentNullException(nameof(key));
        if (iv is not { Length: > 0 })
            throw new ArgumentNullException(nameof(iv));
        
        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.CBC;
        aes.IV = iv;
        aes.Padding = PaddingMode.PKCS7;

        var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

        using var msEncrypt = new MemoryStream();
        using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            //Write all data to the stream.
            swEncrypt.Write(plainText);
        }

        var encrypted = msEncrypt.ToArray();

        return encrypted;
    }
    
    /// <summary>
    /// for merging two bytes arrays
    /// </summary>
    /// <param name="a1">First array</param>
    /// <param name="a2">Second array</param>
    /// <returns></returns>
    private static byte[] Combine(byte[] a1, byte[] a2)
    {
        var ret = new byte[a1.Length + a2.Length];
        Array.Copy(a1, 0, ret, 0, a1.Length);
        Array.Copy(a2, 0, ret, a1.Length, a2.Length);
        return ret;
    }
}