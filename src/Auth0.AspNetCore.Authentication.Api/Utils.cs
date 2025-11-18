using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;

[assembly: InternalsVisibleTo("Auth0.AspNetCore.Authentication.Api.UnitTests")]

namespace Auth0.AspNetCore.Authentication.Api;

public abstract class Utils
{
    /// <summary>
    ///     Creates a Base64-encoded JSON string containing the SDK agent name and version.
    ///     The version is retrieved from the assembly of <see cref="AuthenticationBuilderExtensions" />.
    /// </summary>
    /// <returns>A Base64-encoded JSON string with agent name and version.</returns>
    public static string CreateAgentString()
    {
        Version? sdkVersion = typeof(AuthenticationBuilderExtensions).GetTypeInfo().Assembly.GetName().Version;
        var agentJson =
            $"{{\"name\":\"aspnetcore-api\",\"version\":\"{BuildVersionString(sdkVersion)}\"}}";
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(agentJson));
    }

    internal static string BuildVersionString(Version? sdkVersion)
    {
        return sdkVersion != null
            ? $"{sdkVersion.Major}.{sdkVersion.Minor}.{sdkVersion.Build}"
            : "0.0.0";
    }
}
