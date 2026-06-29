using System.Runtime.CompilerServices;
using System.Text;

[assembly: InternalsVisibleTo("Auth0.AspNetCore.Authentication.Api.UnitTests")]

namespace Auth0.AspNetCore.Authentication.Api;

internal abstract class Utils
{
    /// <summary>
    ///     Creates a Base64-encoded JSON string containing the SDK agent name and version.
    /// </summary>
    /// <returns>A Base64-encoded JSON string with agent name and version.</returns>
    public static string CreateAgentString()
    {
        var agentJson =
            $"{{\"name\":\"aspnetcore-api\",\"version\":\"{Version.Current}\"}}";
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(agentJson));
    }
}
