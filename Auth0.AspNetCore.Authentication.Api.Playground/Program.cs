using Auth0.AspNetCore.Authentication.Api;

using Microsoft.AspNetCore.Authentication.JwtBearer;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Adds Auth0 JWT validation to the API
// Configuration is automatically bound from appsettings.json "Auth0" section
builder.Services.AddAuth0ApiAuthentication(
    builder.Configuration.GetSection("Auth0"),
    configureJwtBearer: jwt =>
    {
        jwt.Events = new JwtBearerEvents
        {
            // Custom event just to log the token received in the request.
            OnMessageReceived = context =>
            {
                Console.WriteLine($"Token extracted? : {(!string.IsNullOrEmpty(context.Token) ? "yes" : "no")}");
                return Task.CompletedTask;
            }
        };
    }).WithDPoP();

builder.Services.AddAuthorization();

WebApplication app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/open-endpoint", () =>
    {
        var responseMessage = "This endpoint is available to all users.";
        return responseMessage;
    })
    .WithName("AccessOpenEndpoint")
    .WithOpenApi();

app.MapGet("/restricted-endpoint", () =>
    {
        var responseMessage = "You are special. This endpoint is available only to select users.";
        return responseMessage;
    })
    .WithName("AccessRestrictedEndpoint")
    .WithOpenApi().RequireAuthorization();

app.Run();
