using Auth0.AspNetCore.Authentication.Api.CustomDomains;

namespace Auth0.AspNetCore.Authentication.Api.UnitTests;

public class TokenValidationHelperTests
{
    [Theory]
    [InlineData("example.com", "https://example.com")]
    [InlineData("example.com/", "https://example.com")]
    [InlineData("https://example.com", "https://example.com")]
    [InlineData("https://example.com/", "https://example.com")]
    [InlineData("http://example.com", "http://example.com")]
    [InlineData("http://example.com/", "http://example.com")]
    public void BuildIssuerUrl_Returns_Domain_With_Scheme_And_No_Trailing_Slash(string domain, string expected)
    {
        var result = TokenValidationHelper.BuildIssuerUrl(domain);

        result.Should().Be(expected);
    }

    [Theory]
    [InlineData("https://example.com/", new[] { "example.com" }, "https://example.com")]
    [InlineData("https://example.com", new[] { "https://example.com" }, "https://example.com")]
    [InlineData("http://example.com", new[] { "http://example.com" }, "http://example.com")]
    [InlineData("https://other.com", new[] { "example.com" }, null)]
    [InlineData(null, new[] { "example.com" }, null)]
    [InlineData("", new[] { "example.com" }, null)]
    public void ValidateIssuer_Returns_Expected_Result(string? issuer, string[] allowedDomains, string? expected)
    {
        var result = TokenValidationHelper.ValidateIssuer(issuer, allowedDomains);

        result.Should().Be(expected);
    }
}
