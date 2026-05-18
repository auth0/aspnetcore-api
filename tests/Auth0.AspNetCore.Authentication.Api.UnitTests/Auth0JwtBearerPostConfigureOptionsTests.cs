using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Auth0.AspNetCore.Authentication.Api.UnitTests;

public class Auth0JwtBearerPostConfigureOptionsTests
{
    [Fact]
    public void PostConfigure_Should_Add_Auth0Client_Header()
    {
        // Arrange
        var postConfigureOptions = new Auth0JwtBearerPostConfigureOptions();
        var jwtBearerOptions = new JwtBearerOptions
        {
            Backchannel = new HttpClient()
        };
        var expectedHeaderValue = Utils.CreateAgentString();

        // Act
        postConfigureOptions.PostConfigure(null, jwtBearerOptions);

        // Assert
        jwtBearerOptions.Backchannel.DefaultRequestHeaders.GetValues("Auth0-Client").First().Should()
            .Be(expectedHeaderValue);
    }
}
