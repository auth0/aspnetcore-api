using System.Net;

using Auth0.AspNetCore.Authentication.Api.DPoP;
using Auth0.AspNetCore.Authentication.Api.DPoP.EventHandlers;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

using Moq;

namespace Auth0.AspNetCore.Authentication.Api.UnitTests;

public class MessageReceivedHandlerTests
{
    private readonly DPoPOptions _dPoPOptions = new();
    private readonly MessageReceivedHandler _handler = new();

    private MessageReceivedContext CreateContext(DPoPModes mode = DPoPModes.Disabled,
        string? authorizationHeader = null)
    {
        // Create a real service collection and provider to handle GetRequiredService
        var services = new ServiceCollection();
        _dPoPOptions.Mode = mode;
        services.AddSingleton(_dPoPOptions);
        ServiceProvider serviceProvider = services.BuildServiceProvider();

        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider
        };

        // Set up the authorization header if provided
        if (authorizationHeader != null)
        {
            httpContext.Request.Headers.Authorization = new StringValues(authorizationHeader);
        }

        var scheme = new AuthenticationScheme("Test", "Test", typeof(JwtBearerHandler));
        var context = new MessageReceivedContext(httpContext, scheme, new JwtBearerOptions())
        {
            Token = "test-token"
        };

        return context;
    }

    [Fact]
    public async Task Handle_When_Mode_Is_Disabled_Should_Complete_Successfully()
    {
        MessageReceivedContext context = CreateContext();

        await _handler.Handle(context);

        // Should not throw any exceptions
        _dPoPOptions.Mode.Should().Be(DPoPModes.Disabled);
    }

    [Fact]
    public async Task Handle_When_Mode_Is_Allowed_Should_Complete_Successfully()
    {
        MessageReceivedContext context = CreateContext(DPoPModes.Allowed, "Bearer token123");

        await _handler.Handle(context);

        // Should not throw any exceptions
        _dPoPOptions.Mode.Should().Be(DPoPModes.Allowed);
    }

    [Fact]
    public async Task Handle_When_Mode_Is_Required_Should_Complete_Successfully()
    {
        MessageReceivedContext context = CreateContext(DPoPModes.Required, "Bearer token123");

        await _handler.Handle(context);

        // Should not throw any exceptions
        _dPoPOptions.Mode.Should().Be(DPoPModes.Required);
    }

    [Fact]
    public async Task Handle_When_Mode_Is_Unknown_Should_Return_Completed_Task()
    {
        MessageReceivedContext context = CreateContext((DPoPModes)999);

        await _handler.Handle(context);

        // Should not throw any exceptions for unknown modes
        _dPoPOptions.Mode.Should().Be((DPoPModes)999);
    }

    [Fact]
    public async Task HandleDisabledMode_Should_Complete_Successfully()
    {
        MessageReceivedContext context = CreateContext();

        await _handler.HandleDisabledMode(context);
    }

    [Fact]
    public async Task HandleAllowedMode_Should_Complete_Successfully()
    {
        MessageReceivedContext context = CreateContext(DPoPModes.Allowed, "Bearer token123");

        await _handler.HandleAllowedMode(context);
    }

    [Fact]
    public async Task HandleRequiredMode_Should_Complete_Successfully()
    {
        MessageReceivedContext context = CreateContext(DPoPModes.Required, "Bearer token123");

        await _handler.HandleRequiredMode(context);
    }

    [Fact]
    public async Task HandleAllowedMode_When_Invalid_Authorization_Header_Count_Should_Handle_Invalid_Request()
    {
        // Create context with multiple authorization headers
        var services = new ServiceCollection();
        _dPoPOptions.Mode = DPoPModes.Allowed;
        services.AddSingleton(_dPoPOptions);
        ServiceProvider serviceProvider = services.BuildServiceProvider();

        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider
        };

        // Add multiple authorization headers
        httpContext.Request.Headers.Append("Authorization", "Bearer token1");
        httpContext.Request.Headers.Append("Authorization", "Bearer token2");

        var scheme = new AuthenticationScheme("Test", "Test", typeof(JwtBearerHandler));
        var context = new MessageReceivedContext(httpContext, scheme, new JwtBearerOptions())
        {
            Token = "test-token"
        };

        await _handler.HandleAllowedMode(context);

        // Should handle invalid request
        context.Result.Should().NotBeNull();
        context.Result!.Failure.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleRequiredMode_When_Authorization_Header_Is_Missing_Should_Log_Debug()
    {
        var logger = new Mock<ILogger<MessageReceivedHandler>>();
        var handler = new MessageReceivedHandler(logger.Object);
        MessageReceivedContext context = CreateContext(DPoPModes.Required);

        await handler.HandleRequiredMode(context);

        logger.Verify(
            x => x.Log(
                LogLevel.Debug,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, _) => v.ToString() == "Missing authorization header in required mode"),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);

        context.Result.Should().NotBeNull();
        context.Result!.Failure.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAllowedMode_When_Bearer_With_DPoP_Proof_Should_Fail_With_InvalidToken()
    {
        // Create context with Bearer scheme but DPoP proof header present
        var services = new ServiceCollection();
        _dPoPOptions.Mode = DPoPModes.Allowed;
        services.AddSingleton(_dPoPOptions);
        ServiceProvider serviceProvider = services.BuildServiceProvider();

        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider
        };

        // Set Bearer authorization with DPoP proof header (conflicting scenario)
        httpContext.Request.Headers.Authorization = new StringValues("Bearer token123");
        httpContext.Request.Headers.Append(Auth0Constants.DPoP.ProofHeader, "proof-token");

        var scheme = new AuthenticationScheme("Test", "Test", typeof(JwtBearerHandler));
        var context = new MessageReceivedContext(httpContext, scheme, new JwtBearerOptions())
        {
            Token = "test-token"
        };

        await _handler.HandleAllowedMode(context);

        // Should set error items and fail
        context.HttpContext.Items[Auth0Constants.DPoP.BearerErrorCode].Should().Be(Auth0Constants.DPoP.Error.Code.InvalidToken);
        context.HttpContext.Items[Auth0Constants.DPoP.BearerErrorDescription].Should().Be(Auth0Constants.DPoP.Error.Description.BearerSchemeWithDPoPProof);
        context.HttpContext.Items[Auth0Constants.DPoP.BearerStatusCode].Should().Be(HttpStatusCode.Unauthorized);
        context.Result.Should().NotBeNull();
        context.Result!.Failure.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAllowedMode_When_DPoP_Scheme_Without_Proof_Header_Should_Handle_Invalid_Request()
    {
        // Create context with DPoP scheme but no DPoP proof header
        var services = new ServiceCollection();
        _dPoPOptions.Mode = DPoPModes.Allowed;
        services.AddSingleton(_dPoPOptions);
        ServiceProvider serviceProvider = services.BuildServiceProvider();

        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider
        };

        // Set DPoP authorization without proof header
        httpContext.Request.Headers.Authorization = new StringValues("DPoP token123");

        var scheme = new AuthenticationScheme("Test", "Test", typeof(JwtBearerHandler));
        var context = new MessageReceivedContext(httpContext, scheme, new JwtBearerOptions())
        {
            Token = "test-token"
        };

        await _handler.HandleAllowedMode(context);

        // Should handle invalid request
        context.Result.Should().NotBeNull();
        context.Result!.Failure.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAllowedMode_When_ExtractDPoPBoundAccessToken_Returns_Null_Should_Handle_Invalid_Request()
    {
        // Create context with DPoP scheme but token extraction fails
        var services = new ServiceCollection();
        _dPoPOptions.Mode = DPoPModes.Allowed;
        services.AddSingleton(_dPoPOptions);
        ServiceProvider serviceProvider = services.BuildServiceProvider();

        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider
        };

        // Set DPoP authorization with just the scheme (no token)
        httpContext.Request.Headers.Authorization = new StringValues("DPoP ");
        httpContext.Request.Headers.Append(Auth0Constants.DPoP.ProofHeader, "proof-token");

        var scheme = new AuthenticationScheme("Test", "Test", typeof(JwtBearerHandler));
        var context = new MessageReceivedContext(httpContext, scheme, new JwtBearerOptions())
        {
            Token = "test-token"
        };

        await _handler.HandleAllowedMode(context);

        // Should handle invalid request
        context.Result.Should().NotBeNull();
        context.Result!.Failure.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleRequiredMode_When_Invalid_Authorization_Header_Count_Should_Handle_Invalid_Request()
    {
        // Create context with multiple authorization headers
        var services = new ServiceCollection();
        _dPoPOptions.Mode = DPoPModes.Required;
        services.AddSingleton(_dPoPOptions);
        ServiceProvider serviceProvider = services.BuildServiceProvider();

        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider
        };

        // Add multiple authorization headers
        httpContext.Request.Headers.Append("Authorization", "DPoP token1");
        httpContext.Request.Headers.Append("Authorization", "DPoP token2");

        var scheme = new AuthenticationScheme("Test", "Test", typeof(JwtBearerHandler));
        var context = new MessageReceivedContext(httpContext, scheme, new JwtBearerOptions())
        {
            Token = "test-token"
        };

        await _handler.HandleRequiredMode(context);

        // Should handle invalid request
        context.Result.Should().NotBeNull();
        context.Result!.Failure.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleRequiredMode_When_Not_DPoP_Scheme_Should_Handle_Invalid_Request()
    {
        // Create context with Bearer scheme in Required mode
        var services = new ServiceCollection();
        _dPoPOptions.Mode = DPoPModes.Required;
        services.AddSingleton(_dPoPOptions);
        ServiceProvider serviceProvider = services.BuildServiceProvider();

        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider
        };

        // Set Bearer authorization in Required mode
        httpContext.Request.Headers.Authorization = new StringValues("Bearer token123");

        var scheme = new AuthenticationScheme("Test", "Test", typeof(JwtBearerHandler));
        var context = new MessageReceivedContext(httpContext, scheme, new JwtBearerOptions())
        {
            Token = "test-token"
        };

        await _handler.HandleRequiredMode(context);

        // Should handle invalid request
        context.Result.Should().NotBeNull();
        context.Result!.Failure.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleRequiredMode_When_DPoP_Scheme_Without_Proof_Header_Should_Handle_Invalid_Request()
    {
        // Create context with DPoP scheme but no DPoP proof header
        var services = new ServiceCollection();
        _dPoPOptions.Mode = DPoPModes.Required;
        services.AddSingleton(_dPoPOptions);
        ServiceProvider serviceProvider = services.BuildServiceProvider();

        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider
        };

        // Set DPoP authorization without proof header
        httpContext.Request.Headers.Authorization = new StringValues("DPoP token123");

        var scheme = new AuthenticationScheme("Test", "Test", typeof(JwtBearerHandler));
        var context = new MessageReceivedContext(httpContext, scheme, new JwtBearerOptions())
        {
            Token = "test-token"
        };

        await _handler.HandleRequiredMode(context);

        // Should handle invalid request
        context.Result.Should().NotBeNull();
        context.Result!.Failure.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleRequiredMode_When_No_Authorization_Token_Exists_Should_Handle_Invalid_Request()
    {
        // Create context with DPoP scheme but empty token
        var services = new ServiceCollection();
        _dPoPOptions.Mode = DPoPModes.Required;
        services.AddSingleton(_dPoPOptions);
        ServiceProvider serviceProvider = services.BuildServiceProvider();

        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider
        };

        // Set DPoP authorization with empty token
        httpContext.Request.Headers.Authorization = new StringValues("DPoP");
        httpContext.Request.Headers.Append(Auth0Constants.DPoP.ProofHeader, "proof-token");

        var scheme = new AuthenticationScheme("Test", "Test", typeof(JwtBearerHandler));
        var context = new MessageReceivedContext(httpContext, scheme, new JwtBearerOptions())
        {
            Token = "test-token"
        };

        await _handler.HandleRequiredMode(context);

        // Should handle invalid request
        context.Result.Should().NotBeNull();
        context.Result!.Failure.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleRequiredMode_When_ExtractDPoPBoundAccessToken_Returns_Null_Should_Handle_Invalid_Request()
    {
        // Create context with DPoP scheme but token extraction fails
        var services = new ServiceCollection();
        _dPoPOptions.Mode = DPoPModes.Required;
        services.AddSingleton(_dPoPOptions);
        ServiceProvider serviceProvider = services.BuildServiceProvider();

        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider
        };

        // Set DPoP authorization with just the scheme and space (no token)
        httpContext.Request.Headers.Authorization = new StringValues("DPoP ");
        httpContext.Request.Headers.Append(Auth0Constants.DPoP.ProofHeader, "proof-token");

        var scheme = new AuthenticationScheme("Test", "Test", typeof(JwtBearerHandler));
        var context = new MessageReceivedContext(httpContext, scheme, new JwtBearerOptions())
        {
            Token = "test-token"
        };

        await _handler.HandleRequiredMode(context);

        // Should handle invalid request
        context.Result.Should().NotBeNull();
        context.Result!.Failure.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAllowedMode_When_ExtractDPoPBoundAccessToken_Returns_Null_Via_Mock_Should_Handle_Invalid_Request()
    {
        // Create a mock handler that returns null from ExtractDPoPBoundAccessToken
        // even when other validations pass
        var mockHandler = new TestMessageReceivedHandlerWithNullExtraction();
        
        var services = new ServiceCollection();
        _dPoPOptions.Mode = DPoPModes.Allowed;
        services.AddSingleton(_dPoPOptions);
        ServiceProvider serviceProvider = services.BuildServiceProvider();

        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider
        };

        // Set up valid DPoP request that will pass all checks except extraction
        httpContext.Request.Headers.Authorization = new StringValues("DPoP validtoken");
        httpContext.Request.Headers.Append(Auth0Constants.DPoP.ProofHeader, "proof-token");

        var scheme = new AuthenticationScheme("Test", "Test", typeof(JwtBearerHandler));
        var context = new MessageReceivedContext(httpContext, scheme, new JwtBearerOptions())
        {
            Token = "test-token"
        };

        await mockHandler.HandleAllowedMode(context);

        // Should handle invalid request when extraction returns null
        context.Result.Should().NotBeNull();
        context.Result!.Failure.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleRequiredMode_When_ExtractDPoPBoundAccessToken_Returns_Null_Via_Mock_Should_Handle_Invalid_Request()
    {
        // Create a mock handler that returns null from ExtractDPoPBoundAccessToken
        // even when other validations pass
        var mockHandler = new TestMessageReceivedHandlerWithNullExtraction();
        
        var services = new ServiceCollection();
        _dPoPOptions.Mode = DPoPModes.Required;
        services.AddSingleton(_dPoPOptions);
        ServiceProvider serviceProvider = services.BuildServiceProvider();

        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider
        };

        // Set up valid DPoP request that will pass all checks except extraction
        httpContext.Request.Headers.Authorization = new StringValues("DPoP validtoken");
        httpContext.Request.Headers.Append(Auth0Constants.DPoP.ProofHeader, "proof-token");

        var scheme = new AuthenticationScheme("Test", "Test", typeof(JwtBearerHandler));
        var context = new MessageReceivedContext(httpContext, scheme, new JwtBearerOptions())
        {
            Token = "test-token"
        };

        await mockHandler.HandleRequiredMode(context);

        // Should handle invalid request when extraction returns null
        context.Result.Should().NotBeNull();
        context.Result!.Failure.Should().NotBeNull();
    }

    // Test helper class that overrides ExtractDPoPBoundAccessToken to return null
    private class TestMessageReceivedHandlerWithNullExtraction : MessageReceivedHandler
    {
        internal override string? ExtractDPoPBoundAccessToken(HttpRequest httpRequest)
        {
            // Always return null to test the null handling path
            return null;
        }
    }

    [Fact]
    public async Task HandleAllowedMode_When_Valid_DPoP_Request_Should_Extract_And_Set_Token()
    {
        // Create context with valid DPoP scheme, token, and proof header
        var services = new ServiceCollection();
        _dPoPOptions.Mode = DPoPModes.Allowed;
        services.AddSingleton(_dPoPOptions);
        ServiceProvider serviceProvider = services.BuildServiceProvider();

        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider
        };

        var expectedToken = "valid-dpop-access-token";
        httpContext.Request.Headers.Authorization = new StringValues($"DPoP {expectedToken}");
        httpContext.Request.Headers.Append(Auth0Constants.DPoP.ProofHeader, "valid-proof-token");

        var scheme = new AuthenticationScheme("Test", "Test", typeof(JwtBearerHandler));
        var context = new MessageReceivedContext(httpContext, scheme, new JwtBearerOptions())
        {
            Token = "initial-token"
        };

        await _handler.HandleAllowedMode(context);

        // Should extract and set the DPoP token
        context.Token.Should().Be(expectedToken);
        context.Result.Should().BeNull(); // No failure
    }

    [Fact]
    public async Task HandleRequiredMode_When_Valid_DPoP_Request_Should_Extract_And_Set_Token()
    {
        // Create context with valid DPoP scheme, token, and proof header
        var services = new ServiceCollection();
        _dPoPOptions.Mode = DPoPModes.Required;
        services.AddSingleton(_dPoPOptions);
        ServiceProvider serviceProvider = services.BuildServiceProvider();

        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider
        };

        var expectedToken = "valid-dpop-access-token";
        httpContext.Request.Headers.Authorization = new StringValues($"DPoP {expectedToken}");
        httpContext.Request.Headers.Append(Auth0Constants.DPoP.ProofHeader, "valid-proof-token");

        var scheme = new AuthenticationScheme("Test", "Test", typeof(JwtBearerHandler));
        var context = new MessageReceivedContext(httpContext, scheme, new JwtBearerOptions())
        {
            Token = "initial-token"
        };

        await _handler.HandleRequiredMode(context);

        // Should extract and set the DPoP token
        context.Token.Should().Be(expectedToken);
        context.Result.Should().BeNull(); // No failure
    }
}
