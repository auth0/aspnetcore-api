using Auth0.AspNetCore.Authentication.Api.CustomDomains;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Moq;

namespace Auth0.AspNetCore.Authentication.Api.UnitTests.CustomDomains;

public class NullConfigurationManagerCacheTests
{
    [Fact]
    public void GetOrCreate_AlwaysInvokesFactory()
    {
        // Arrange
        var cache = new NullConfigurationManagerCache();
        var mockManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        var factoryCallCount = 0;

        // Act
        IConfigurationManager<OpenIdConnectConfiguration> result1 = cache.GetOrCreate("https://test.com/.well-known/openid-configuration",
            _ =>
            {
                factoryCallCount++;
                return mockManager.Object;
            });

        IConfigurationManager<OpenIdConnectConfiguration> result2 = cache.GetOrCreate("https://test.com/.well-known/openid-configuration",
            _ =>
            {
                factoryCallCount++;
                return mockManager.Object;
            });

        // Assert
        factoryCallCount.Should().Be(2, "factory should be called every time, no caching");
        result1.Should().BeSameAs(mockManager.Object);
        result2.Should().BeSameAs(mockManager.Object);
    }

    [Fact]
    public void GetOrCreate_WithDifferentAddresses_InvokesFactoryForEach()
    {
        // Arrange
        var cache = new NullConfigurationManagerCache();
        var mockManager1 = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        var mockManager2 = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        var factoryCallCount = 0;

        // Act
        IConfigurationManager<OpenIdConnectConfiguration> result1 = cache.GetOrCreate("https://test1.com/.well-known/openid-configuration",
            _ =>
            {
                factoryCallCount++;
                return mockManager1.Object;
            });

        IConfigurationManager<OpenIdConnectConfiguration> result2 = cache.GetOrCreate("https://test2.com/.well-known/openid-configuration",
            _ =>
            {
                factoryCallCount++;
                return mockManager2.Object;
            });

        // Assert
        factoryCallCount.Should().Be(2, "factory should be called for each address");
        result1.Should().BeSameAs(mockManager1.Object);
        result2.Should().BeSameAs(mockManager2.Object);
    }

    [Fact]
    public void GetOrCreate_PassesMetadataAddressToFactory()
    {
        // Arrange
        var cache = new NullConfigurationManagerCache();
        const string expectedAddress = "https://test.com/.well-known/openid-configuration";
        string? receivedAddress = null;

        // Act
        cache.GetOrCreate(expectedAddress,
            address =>
            {
                receivedAddress = address;
                return Mock.Of<IConfigurationManager<OpenIdConnectConfiguration>>();
            });

        // Assert
        receivedAddress.Should().Be(expectedAddress, "metadata address should be passed to factory");
    }

    [Fact]
    public void Clear_DoesNotThrow()
    {
        // Arrange
        var cache = new NullConfigurationManagerCache();

        // Act
        Action act = () => cache.Clear();

        // Assert
        act.Should().NotThrow("Clear is a no-op and should never throw");
    }

    [Fact]
    public void Dispose_DoesNotThrow()
    {
        // Arrange
        var cache = new NullConfigurationManagerCache();

        // Act
        Action act = () => cache.Dispose();

        // Assert
        act.Should().NotThrow("Dispose is a no-op and should never throw");
    }

    [Fact]
    public void GetOrCreate_WithSameAddressRepeated_NeverCaches()
    {
        // Arrange
        var cache = new NullConfigurationManagerCache();
        var callCount = 0;
        const string address = "https://test.com/.well-known/openid-configuration";

        // Act
        for (int i = 0; i < 10; i++)
        {
            cache.GetOrCreate(address, _ =>
            {
                callCount++;
                return Mock.Of<IConfigurationManager<OpenIdConnectConfiguration>>();
            });
        }

        // Assert
        callCount.Should().Be(10, "factory should be called every time, demonstrating no caching");
    }

    [Fact]
    public void GetOrCreate_WithNullFactory_ThrowsNullReferenceException()
    {
        // Arrange
        var cache = new NullConfigurationManagerCache();

        // Act
        Action act = () => cache.GetOrCreate("https://test.com/.well-known/openid-configuration", null!);

        // Assert
        act.Should().Throw<NullReferenceException>("null factory should throw");
    }

    [Fact]
    public void GetOrCreate_WithFactoryReturningNull_ReturnsNull()
    {
        // Arrange
        var cache = new NullConfigurationManagerCache();

        // Act
        IConfigurationManager<OpenIdConnectConfiguration> result = cache.GetOrCreate("https://test.com/.well-known/openid-configuration", _ => null!);

        // Assert
        result.Should().BeNull("factory return value should be passed through");
    }

    [Fact]
    public void GetOrCreate_WithFactoryThrowing_PropagatesException()
    {
        // Arrange
        var cache = new NullConfigurationManagerCache();
        var expectedException = new InvalidOperationException("Test exception");

        // Act
        Action act = () => cache.GetOrCreate("https://test.com/.well-known/openid-configuration",
            _ => throw expectedException);

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .Which.Should().BeSameAs(expectedException, "factory exceptions should propagate");
    }
}
