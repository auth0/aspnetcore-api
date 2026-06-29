using System.Text;

namespace Auth0.AspNetCore.Authentication.Api.UnitTests;

public class UtilsTests
{
    [Fact]
    public void CreateAgentString_ReturnsBase64EncodedJson_With_Correct_Name_And_Version()
    {
        var agentString = Utils.CreateAgentString();
        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(agentString));
        decoded.Should().Contain("\"name\":\"aspnetcore-api\"");
        decoded.Should().Contain($"\"version\":\"{Version.Current}\"");
    }

    [Fact]
    public void CreateAgentString_Returns_Valid_Base64_String()
    {
        var agentString = Utils.CreateAgentString();
        Action act = () => Convert.FromBase64String(agentString);
        act.Should().NotThrow();
    }
}
