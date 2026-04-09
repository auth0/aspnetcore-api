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

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void IsUnsupportedAlgorithm_WithNullOrEmpty_ReturnsTrue(string? algorithm)
    {
        TokenValidationHelper.IsUnsupportedAlgorithm(algorithm).Should().BeTrue();
    }

    [Theory]
    [InlineData("none")]
    [InlineData("NONE")]
    [InlineData("None")]
    [InlineData("nOnE")]
    public void IsUnsupportedAlgorithm_WithNoneAlgorithm_ReturnsTrue(string algorithm)
    {
        TokenValidationHelper.IsUnsupportedAlgorithm(algorithm).Should().BeTrue();
    }

    [Theory]
    [InlineData("HS256")]
    [InlineData("HS384")]
    [InlineData("HS512")]
    [InlineData("hs256")]
    [InlineData("Hs512")]
    public void IsUnsupportedAlgorithm_WithHsAlgorithms_ReturnsTrue(string algorithm)
    {
        TokenValidationHelper.IsUnsupportedAlgorithm(algorithm).Should().BeTrue();
    }

    [Theory]
    [InlineData("RS256")]
    [InlineData("RS384")]
    [InlineData("RS512")]
    [InlineData("ES256")]
    [InlineData("ES384")]
    [InlineData("ES512")]
    [InlineData("PS256")]
    [InlineData("PS384")]
    [InlineData("PS512")]
    [InlineData("EdDSA")]
    public void IsUnsupportedAlgorithm_WithAsymmetricAlgorithms_ReturnsFalse(string algorithm)
    {
        TokenValidationHelper.IsUnsupportedAlgorithm(algorithm).Should().BeFalse();
    }
}
