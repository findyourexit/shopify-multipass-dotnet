using System.Text.Json.Serialization;

namespace ShopifyMultipass.Models;

/// <summary>
/// A base class that holds customer data. Containing only the required fields outlined in the official Shopify developer docs. In order to include optional fields representing further customer details (such as <c>first_name</c>, <c>last_name</c>, etc.) inherit from this class.
/// </summary>
public class Customer
{
    [JsonPropertyName("email")]
    public required string Email { get; set; }
    [JsonPropertyName("created_at")]
    public string CreatedAt { get; set; } = DateTime.Now.ToString(@"yyyy-MM-ddTHH\:mm\:sszzz");
}