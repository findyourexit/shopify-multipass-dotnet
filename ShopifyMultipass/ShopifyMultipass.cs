using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace ShopifyMultipass;

public sealed class ShopifyMultipass
{
    private readonly byte[] _encryptionKey;
    private readonly byte[] _signatureKey;
    private readonly string _redirectUrl;

    /// <summary>
    /// Initialise the ShopifyMultipass class with your Multipass secret and Shopify domain.
    /// </summary>
    /// <param name="secret">(<c>Required</c>) This can be found in the Multipass section of your Shopify Admin (once Multipass has been enabled).</param>
    /// <param name="domain">(<c>Required</c>) This is needed for redirecting once the token has been generated.</param>
    /// <exception cref="ArgumentNullException">Omitting either of the required constructor arguments will throw an <c>ArgumentNullException</c>. This includes for the case where an empty or whitespace string is provided for either argument.</exception>
    public ShopifyMultipass(string secret, string domain)
    {
        if (string.IsNullOrWhiteSpace(secret))
            throw new ArgumentNullException(nameof(secret), "A Multipass secret is required. This can be found in the Multipass section of your Shopify Admin (once Multipass has been enabled).");

        if (string.IsNullOrWhiteSpace(domain))
            throw new ArgumentNullException(nameof(domain), "Please specify your Shopify domain. This is needed for redirecting once the token has been generated.");

        // Use the secret to generate an encryption key and a signature key.
        var keyMaterial = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
        _encryptionKey = new ArraySegment<byte>(keyMaterial, 0, 16).ToArray();
        _signatureKey = new ArraySegment<byte>(keyMaterial, 16, 16).ToArray();
        _redirectUrl = $"https://{domain}/account/login/multipass/";
    }

    /// <summary>
    /// Generate a Shopify Multipass token for the provided customer JSON data.
    /// </summary>
    /// <param name="customerJson">(<c>Required</c>) JSON representation of the customer data.</param>
    /// <returns>A Shopify Multipass token.</returns>
    /// <exception cref="ArgumentNullException">Omitting the required <c>customerJson</c> argument will throw an <c>ArgumentNullException</c>. This includes for the case where an empty or whitespace string is provided.</exception>
    public string GenerateToken(string customerJson)
    {
        if (string.IsNullOrWhiteSpace(customerJson))
            throw new ArgumentNullException(nameof(customerJson), "The provided customer JSON string is null, empty or contains only whitespaces.");

        // Encrypt the provided customer JSON data.
        var cipher = Encrypt(customerJson);

        // Create a signature (message authentication code) of the cipher byte array.
        var signature = Sign(cipher);
        
        // Combine and encode everything using URL-safe Base64 (RFC 4648).
        var payload = Combine(cipher, signature);
        var token = Base64UrlEncoder.Encode(payload)!;
        
        // Return the redirect URL with the token appended.
        return _redirectUrl + token;
    }

    /// <summary>
    /// Encrypt plaintext using AES in CBC mode with a random IV.
    /// </summary>
    /// <param name="plaintext">(<c>Required</c>) Input text for encryption.</param>
    /// <returns>A byte array representing the encrypted <c>plaintext</c>.</returns>
    private byte[] Encrypt(string plaintext)
    {
        // Generate an initialization vector (IV).
        var iv = new byte[16];
        
        // Use a secure PRNG to generate a random IV.
        using (var rng = RandomNumberGenerator.Create())
        {
            // Fill the array with cryptographically secure random bytes.
            rng.GetBytes(iv);
        }

        // Encrypt the string to an array of bytes.
        var cipherData = EncryptStringToBytes(plaintext, _encryptionKey, iv);
        
        // Append the encrypted cipher data to the initialization vector.
        return Combine(iv, cipherData);
    }
    
    /// <summary>
    /// Create a signature (message authentication code) of the cipher array of bytes using <c>HMAC-SHA256</c> with the secret key.
    /// </summary>
    /// <param name="cipher">An encrypted array of bytes representing the customer JSON data.</param>
    /// <returns>A signature (message authentication code) of the <c>cipher</c></returns>
    private byte[] Sign(byte[] cipher)
    {
        var hasher = new HMACSHA256(_signatureKey);
        return hasher.ComputeHash(cipher);
    }
    
    /// <summary>
    /// Encrypt the provided plaintext using AES in CBC mode with the provided key and initialisation vector (IV).
    /// </summary>
    /// <param name="plaintext">(<c>Required</c>) Customer data that is to be encrypted.</param>
    /// <param name="key">(<c>Required</c>) A generated encryption key, based on the provided Shopify Multipass secret.</param>
    /// <param name="iv">(<c>Required</c>) A generated initialization vector (IV).</param>
    /// <returns>The provided customer data, encrypted as a byte array.</returns>
    /// <exception cref="ArgumentNullException">An <c>ArgumentNullException</c> will be thrown if any of the method arguments are null or empty.</exception>
    private static byte[] EncryptStringToBytes(string plaintext, byte[] key, byte[] iv)
    {
        // Run a few checks to ensure the provided arguments are valid.
        if (plaintext is not { Length: > 0 })
            throw new ArgumentNullException(nameof(plaintext));
        if (key is not { Length: > 0 })
            throw new ArgumentNullException(nameof(key));
        if (iv is not { Length: > 0 })
            throw new ArgumentNullException(nameof(iv));
        
        // Create an AES object with the specified key and initialization vector (IV).
        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.CBC;
        aes.IV = iv;
        aes.Padding = PaddingMode.PKCS7;

        // Create an encryptor to perform the stream transform.
        var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

        // Create the streams used for encryption.
        using var msEncrypt = new MemoryStream();
        using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            // Write all data to the stream.
            swEncrypt.Write(plaintext);
        }

        // Return the encrypted bytes from the memory stream.
        return msEncrypt.ToArray();
    }
    
    /// <summary>
    /// Combine two byte arrays into one.
    /// </summary>
    /// <param name="a1">(<c>Required</c>) The first byte array to be combined.</param>
    /// <param name="a2">(<c>Required</c>) The second byte array to be combined.</param>
    /// <returns>A single byte array representing a combination of the provided <c>a1</c> and <c>a2</c> byte arrays.</returns>
    private static byte[] Combine(byte[] a1, byte[] a2)
    {
        var ret = new byte[a1.Length + a2.Length];
        Array.Copy(a1, 0, ret, 0, a1.Length);
        Array.Copy(a2, 0, ret, a1.Length, a2.Length);
        return ret;
    }
}