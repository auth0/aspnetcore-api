using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Auth0.AspNetCore.Authentication.Api.UnitTests;

public class JwtBearerEventsFactoryTests
{
    [Fact]
    public void Create_WithNullEvents_ReturnsJwtBearerEventsWithProxiedHandlers()
    {
        // Act
        JwtBearerEvents result = JwtBearerEventsFactory.Create(null);

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
        JwtBearerEvents result = JwtBearerEventsFactory.Create(existingEvents);
        await result.OnMessageReceived(TestUtilities.CreateMessageReceivedContext());

        // Assert
        userHandlerCalled.Should().BeTrue();
    }
}
