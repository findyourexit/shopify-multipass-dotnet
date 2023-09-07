# :shopping: Shopify Multipass for .NET (7.0)

Available to [Shopify Plus](https://www.shopify.com/plus) merchants, [Multipass](https://shopify.dev/docs/api/multipass) is an industry-standard mechanism for implementing [single sign-on (SSO)](https://en.wikipedia.org/wiki/Single_sign-on) between a Shopify store and a third-party service.

The [Shopify Multipass](https://shopify.dev/docs/api/multipass) mechanism makes use of a secret (`string`) to generate a valid (encrypted) Multipass login token. The required secret can be procured from the Shopify admin portal (after enabling Multipass).

## :wrench:	Under the Hood
This .NET implementation of [Shopify Multipass](https://shopify.dev/docs/api/multipass) token generation endeavours to align as closely as possible to the [official implementation guidelines](https://shopify.dev/docs/api/multipass#example-implementation) provided in the Shopify developer documentation.

In the case of this package, after instantiating `ShopifyMultipass` with the required `secret` and `domain` (see Usage for more information), the secret is used to derive two cryptographic keys — one for encryption and one for signing. 

This key derivation is done through the use of the [SHA-256](https://en.wikipedia.org/wiki/SHA-2) hash function (the first 128 bit are used as encryption key and the last 128 bit are used as signature key). The encryption provides confidentiality. It makes sure that no one can read the customer data. As encryption cipher, we use the [AES algorithm](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) (128 bit key length, [CBC mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) of operation, random [initialization vector](https://en.wikipedia.org/wiki/Initialization_vector)).

## :package: Installation

#### NuGet Package Manager Console :cog:
```powershell
Install-Package Shopify.Multipass
```

## :hammer: Usage
```csharp
// TODO
```

## :file_folder:	 References
- [Shopify Multipass](https://shopify.dev/docs/api/multipass)