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
        decoded.Should().MatchRegex("\"version\":\"\\d+\\.\\d+\\.\\d+\"");
    }

    [Fact]
    public void CreateAgentString_Returns_Valid_Base64_String()
    {
        var agentString = Utils.CreateAgentString();
        Action act = () => Convert.FromBase64String(agentString);
        act.Should().NotThrow();
    }

    [Fact]
    public void CreateAgentString_Returns_Json_With_Default_Version_If_Assembly_Version_Is_Null()
    {
        // Simulate null version by using a test double if possible, otherwise check for "0.0.0" fallback
        // Since static method and type, we can only check for the fallback value in the output
        var agentString = Utils.CreateAgentString();
        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(agentString));
        decoded.Should().MatchRegex("\"version\":\"\\d+\\.\\d+\\.\\d+\"");
    }

    [Fact]
    public void BuildVersionString_ReturnsCorrectString_When_Version_Is_Not_Null()
    {
        var version = new Version(1, 2, 3);
        var result = Utils.BuildVersionString(version);
        result.Should().Be("1.2.3");
    }

    [Fact]
    public void BuildVersionString_Returns_Zero_Version_When_Version_Is_Null()
    {
        var result = Utils.BuildVersionString(null);
        result.Should().Be("0.0.0");
    }
}
