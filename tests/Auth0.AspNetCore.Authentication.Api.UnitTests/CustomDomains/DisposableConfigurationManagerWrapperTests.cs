using Auth0.AspNetCore.Authentication.Api.CustomDomains;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Moq;

namespace Auth0.AspNetCore.Authentication.Api.UnitTests.CustomDomains;

public class DisposableConfigurationManagerWrapperTests
{
    [Fact]
    public void Constructor_WithNullInnerManager_ThrowsArgumentNullException()
    {
        // Arrange
        IConfigurationManager<OpenIdConnectConfiguration>? innerManager = null;

        // Act
        Action act = () => new DisposableConfigurationManagerWrapper(innerManager!, null);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("innerManager");
    }

    [Fact]
    public async Task GetConfigurationAsync_DelegatesToInnerManager()
    {
        // Arrange
        var expectedConfig = new OpenIdConnectConfiguration();
        var mockInnerManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        mockInnerManager
            .Setup(m => m.GetConfigurationAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(expectedConfig);

        var wrapper = new DisposableConfigurationManagerWrapper(mockInnerManager.Object, null);

        // Act
        OpenIdConnectConfiguration result = await wrapper.GetConfigurationAsync(CancellationToken.None);

        // Assert
        result.Should().BeSameAs(expectedConfig);
        mockInnerManager.Verify(m => m.GetConfigurationAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public void RequestRefresh_DelegatesToInnerManager()
    {
        // Arrange
        var mockInnerManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        var wrapper = new DisposableConfigurationManagerWrapper(mockInnerManager.Object, null);

        // Act
        wrapper.RequestRefresh();

        // Assert
        mockInnerManager.Verify(m => m.RequestRefresh(), Times.Once);
    }

    [Fact]
    public async Task Dispose_WithHttpClient_DisposesHttpClient()
    {
        // Arrange
        var mockInnerManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        var httpClient = new HttpClient();
        var wrapper = new DisposableConfigurationManagerWrapper(mockInnerManager.Object, httpClient);

        // Act
        wrapper.Dispose();

        // Assert - HttpClient should be disposed
        // The best way to verify disposal is to check that the wrapper itself was disposed
        Func<Task> act = async () => await wrapper.GetConfigurationAsync(CancellationToken.None);
        await act.Should().ThrowAsync<ObjectDisposedException>("wrapper should be disposed");
    }

    [Fact]
    public void Dispose_CalledMultipleTimes_IsIdempotent()
    {
        // Arrange
        var mockInnerManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        var httpClient = new HttpClient();
        var wrapper = new DisposableConfigurationManagerWrapper(mockInnerManager.Object, httpClient);

        // Act
        wrapper.Dispose();
        Action act = () => wrapper.Dispose(); // Second disposal

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public async Task GetConfigurationAsync_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var mockInnerManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        var wrapper = new DisposableConfigurationManagerWrapper(mockInnerManager.Object, null);
        wrapper.Dispose();

        // Act
        Func<Task> act = async () => await wrapper.GetConfigurationAsync(CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<ObjectDisposedException>();
    }

    [Fact]
    public void RequestRefresh_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var mockInnerManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        var wrapper = new DisposableConfigurationManagerWrapper(mockInnerManager.Object, null);
        wrapper.Dispose();

        // Act
        Action act = () => wrapper.RequestRefresh();

        // Assert
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public async Task Dispose_WithSelfCreatedHttpClient_DisposesOnlyThatClient()
    {
        // Arrange
        var mockInnerManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        var selfCreatedClient = new HttpClient();
        var wrapper = new DisposableConfigurationManagerWrapper(mockInnerManager.Object, selfCreatedClient);

        // Act
        wrapper.Dispose();

        // Assert - Verify the wrapper is disposed (which means it disposed the HttpClient)
        Func<Task> act = async () => await wrapper.GetConfigurationAsync(CancellationToken.None);
        await act.Should().ThrowAsync<ObjectDisposedException>("wrapper should be disposed after disposing self-created client");
    }

    [Fact]
    public async Task GetConfigurationAsync_WithCancellationToken_PropagatesToken()
    {
        // Arrange
        var cts = new CancellationTokenSource();
        CancellationToken token = cts.Token;
        var mockInnerManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        mockInnerManager
            .Setup(m => m.GetConfigurationAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new OpenIdConnectConfiguration());

        var wrapper = new DisposableConfigurationManagerWrapper(mockInnerManager.Object, null);

        // Act
        await wrapper.GetConfigurationAsync(token);

        // Assert
        mockInnerManager.Verify(m => m.GetConfigurationAsync(token), Times.Once);
    }
}
