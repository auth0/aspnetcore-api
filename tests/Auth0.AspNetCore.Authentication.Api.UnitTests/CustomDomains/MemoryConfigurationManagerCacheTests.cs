using Auth0.AspNetCore.Authentication.Api.CustomDomains;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Moq;

namespace Auth0.AspNetCore.Authentication.Api.UnitTests.CustomDomains;

public class MemoryConfigurationManagerCacheTests
{
    [Fact]
    public void Constructor_WithZeroMaxSize_ThrowsArgumentOutOfRangeException()
    {
        // Act
        Action act = () => new MemoryConfigurationManagerCache(0);

        // Assert
        act.Should().Throw<ArgumentOutOfRangeException>()
            .WithParameterName("maxSize");
    }

    [Fact]
    public void Constructor_WithNegativeMaxSize_ThrowsArgumentOutOfRangeException()
    {
        // Act
        Action act = () => new MemoryConfigurationManagerCache(-1);

        // Assert
        act.Should().Throw<ArgumentOutOfRangeException>()
            .WithParameterName("maxSize");
    }

    [Fact]
    public void GetOrCreate_FirstCall_InvokesFactory()
    {
        // Arrange
        var cache = new MemoryConfigurationManagerCache();
        var mockManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        var factoryCalled = false;

        // Act
        IConfigurationManager<OpenIdConnectConfiguration> result = cache.GetOrCreate("https://test.com/.well-known/openid-configuration",
            _ =>
            {
                factoryCalled = true;
                return mockManager.Object;
            });

        // Assert
        factoryCalled.Should().BeTrue();
        result.Should().BeSameAs(mockManager.Object);
    }

    [Fact]
    public void GetOrCreate_SecondCall_ReturnsCachedInstance()
    {
        // Arrange
        var cache = new MemoryConfigurationManagerCache();
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
                return Mock.Of<IConfigurationManager<OpenIdConnectConfiguration>>();
            });

        // Assert
        factoryCallCount.Should().Be(1, "factory should only be called once");
        result1.Should().BeSameAs(result2, "cached instance should be returned");
    }

    [Fact]
    public void GetOrCreate_DifferentMetadataAddresses_CreatesMultipleInstances()
    {
        // Arrange
        var cache = new MemoryConfigurationManagerCache();
        var mockManager1 = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        var mockManager2 = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();

        // Act
        IConfigurationManager<OpenIdConnectConfiguration> result1 = cache.GetOrCreate("https://test1.com/.well-known/openid-configuration",
            _ => mockManager1.Object);

        IConfigurationManager<OpenIdConnectConfiguration> result2 = cache.GetOrCreate("https://test2.com/.well-known/openid-configuration",
            _ => mockManager2.Object);

        // Assert
        result1.Should().BeSameAs(mockManager1.Object);
        result2.Should().BeSameAs(mockManager2.Object);
        result1.Should().NotBeSameAs(result2);
    }

    [Fact]
    public void GetOrCreate_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var cache = new MemoryConfigurationManagerCache();
        cache.Dispose();

        // Act
        Action act = () => cache.GetOrCreate("https://test.com/.well-known/openid-configuration",
            _ => Mock.Of<IConfigurationManager<OpenIdConnectConfiguration>>());

        // Assert
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Clear_AfterDispose_DoesNotThrow()
    {
        // Arrange
        var cache = new MemoryConfigurationManagerCache();
        cache.Dispose();

        // Act
        Action act = () => cache.Clear();

        // Assert
        act.Should().NotThrow("Clear should be safe to call after disposal");
    }

    [Fact]
    public void Dispose_CalledMultipleTimes_IsIdempotent()
    {
        // Arrange
        var cache = new MemoryConfigurationManagerCache();

        // Act
        cache.Dispose();
        Action act = () => cache.Dispose();

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void Clear_RemovesAllCachedEntries()
    {
        // Arrange
        var cache = new MemoryConfigurationManagerCache();
        var factoryCallCount = 0;
        var mockManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();

        cache.GetOrCreate("https://test.com/.well-known/openid-configuration",
            _ =>
            {
                factoryCallCount++;
                return mockManager.Object;
            });

        // Act
        cache.Clear();

        cache.GetOrCreate("https://test.com/.well-known/openid-configuration",
            _ =>
            {
                factoryCallCount++;
                return mockManager.Object;
            });

        // Assert
        factoryCallCount.Should().Be(2, "factory should be called again after clear");
    }

    [Fact]
    public void GetOrCreate_ConcurrentCalls_SameKey_OnlyInvokesFactoryOnce()
    {
        // Arrange
        var cache = new MemoryConfigurationManagerCache();
        var factoryCallCount = 0;
        var factoryLock = new object();
        var mockManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();

        // Act
        Task<IConfigurationManager<OpenIdConnectConfiguration>>[] tasks = Enumerable.Range(0, 10).Select(_ => Task.Run(() =>
        {
            return cache.GetOrCreate("https://test.com/.well-known/openid-configuration",
                _ =>
                {
                    lock (factoryLock)
                    {
                        factoryCallCount++;
                    }
                    Thread.Sleep(10); // Simulate some work
                    return mockManager.Object;
                });
        })).ToArray();

        Task.WaitAll(tasks);

        // Assert
        factoryCallCount.Should().Be(1, "factory should only be called once even with concurrent access");
        foreach (Task<IConfigurationManager<OpenIdConnectConfiguration>> task in tasks)
        {
            task.Result.Should().BeSameAs(mockManager.Object);
        }
    }

    [Fact]
    public async Task Clear_And_Dispose_Concurrent_DoesNotThrow()
    {
        // Arrange
        var cache = new MemoryConfigurationManagerCache();

        // Add some entries
        cache.GetOrCreate("https://test1.com/.well-known/openid-configuration",
            _ => Mock.Of<IConfigurationManager<OpenIdConnectConfiguration>>());
        cache.GetOrCreate("https://test2.com/.well-known/openid-configuration",
            _ => Mock.Of<IConfigurationManager<OpenIdConnectConfiguration>>());

        // Act
        var clearTask = Task.Run(() =>
        {
            for (int i = 0; i < 100; i++)
            {
                try
                {
                    cache.Clear();
                }
                catch (ObjectDisposedException)
                {
                    // Expected if dispose happens first
                }
                Thread.Sleep(1);
            }
        });

        var disposeTask = Task.Run(() =>
        {
            Thread.Sleep(50);
            cache.Dispose();
        });

        // Assert
        Func<Task> act = async () => await Task.WhenAll(clearTask, disposeTask);
        await act.Should().NotThrowAsync("concurrent Clear and Dispose should be thread-safe");
    }

    [Fact]
    public void GetOrCreate_WithSlidingExpiration_EventuallyEvictsEntries()
    {
        // Arrange
        var cache = new MemoryConfigurationManagerCache(
            maxSize: 100,
            slidingExpiration: TimeSpan.FromMilliseconds(100));

        var factoryCallCount = 0;
        var mockManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();

        // Act - Create entry
        cache.GetOrCreate("https://test.com/.well-known/openid-configuration",
            _ =>
            {
                factoryCallCount++;
                return mockManager.Object;
            });

        // Wait for sliding expiration
        Thread.Sleep(150);

        // Trigger cache compaction by accessing after expiration
        cache.GetOrCreate("https://other.com/.well-known/openid-configuration",
            _ => Mock.Of<IConfigurationManager<OpenIdConnectConfiguration>>());

        // Try to get expired entry (should invoke factory again)
        cache.GetOrCreate("https://test.com/.well-known/openid-configuration",
            _ =>
            {
                factoryCallCount++;
                return mockManager.Object;
            });

        // Assert
        factoryCallCount.Should().Be(2, "expired entry should cause factory to be invoked again");
    }

    [Fact]
    public void GetOrCreate_WithMaxSizeReached_EvictsOldEntries()
    {
        // Arrange
        var cache = new MemoryConfigurationManagerCache(maxSize: 2);
        var disposedManagers = new List<string>();

        // Act - Add 3 entries (exceeds max size of 2)
        IConfigurationManager<OpenIdConnectConfiguration> manager1 = CreateDisposableManager("manager1", disposedManagers);
        IConfigurationManager<OpenIdConnectConfiguration> manager2 = CreateDisposableManager("manager2", disposedManagers);
        IConfigurationManager<OpenIdConnectConfiguration> manager3 = CreateDisposableManager("manager3", disposedManagers);

        cache.GetOrCreate("https://test1.com/.well-known/openid-configuration", _ => manager1);
        cache.GetOrCreate("https://test2.com/.well-known/openid-configuration", _ => manager2);
        cache.GetOrCreate("https://test3.com/.well-known/openid-configuration", _ => manager3);

        // Wait for eviction callback
        Thread.Sleep(200);

        // Assert
        disposedManagers.Should().ContainSingle("one entry should be evicted when max size is exceeded");
    }

    private static IConfigurationManager<OpenIdConnectConfiguration> CreateDisposableManager(
        string name,
        List<string> disposedManagers)
    {
        var mock = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        mock.As<IDisposable>()
            .Setup(m => m.Dispose())
            .Callback(() => disposedManagers.Add(name));
        return mock.Object;
    }
}
