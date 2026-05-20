using Auth0.AspNetCore.Authentication.Api.DPoP;

using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Auth0.AspNetCore.Authentication.Api.UnitTests;

public class DPoPEventsFactoryTests
{
    [Fact]
    public void Create_WithNullEvents_ReturnsJwtBearerEventsWithDPoPHandlers()
    {
        // Act
        JwtBearerEvents result = DPoPEventsFactory.Create(null);

        // Assert
        result.Should().NotBeNull();
        result.OnTokenValidated.Should().NotBeNull();
        result.OnAuthenticationFailed.Should().NotBeNull();
        result.OnMessageReceived.Should().NotBeNull();
        result.OnChallenge.Should().NotBeNull();
        result.OnForbidden.Should().NotBeNull();
    }

    [Fact]
    public async Task Create_WithExistingEvents_PreservesUserHandlers()
    {
        // Arrange
        var userHandlerCalled = false;
        var existingEvents = new JwtBearerEvents
        {
            OnMessageReceived = _ =>
            {
                userHandlerCalled = true;
                return Task.CompletedTask;
            }
        };

        // Act
        JwtBearerEvents result = DPoPEventsFactory.Create(existingEvents);

        // Create a context with DPoP services available
        var context = TestUtilities.CreateMessageReceivedContext()
            .WithDPoPOptions(new DPoPOptions());

        await result.OnMessageReceived(context);

        // Assert - user handler is called after DPoP handler in the chain
        userHandlerCalled.Should().BeTrue();
    }
}
