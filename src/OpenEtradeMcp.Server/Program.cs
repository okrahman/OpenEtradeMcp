using OpenEtradeMcp;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenApiMcpNet;
using Serilog;

try
{
    Console.Error.WriteLine("E*TRADE MCP Server starting...");

    var configuration = new ConfigurationBuilder()
            .AddEnvironmentVariables(prefix: "ETRADE_")
            .AddCommandLine(args)
            .Build();

    // Create E*TRADE configuration
    var etradeConfig = new ETradeConfig();
    configuration.Bind(etradeConfig);

    if (string.IsNullOrEmpty(etradeConfig.ConsumerKey) || string.IsNullOrEmpty(etradeConfig.ConsumerSecret))
    {
        Console.Error.WriteLine("E*TRADE API credentials not provided.");
        Console.Error.WriteLine("Set environment variables ETRADE_CONSUMERKEY and ETRADE_CONSUMERSECRET");
        Console.Error.WriteLine("Or pass them as command line arguments: --ConsumerKey=your-key --ConsumerSecret=your-secret --UseSandbox=true");
        return 1;
    }

    Console.Error.WriteLine($"E*TRADE API Base URL: {etradeConfig.BaseUrl}");
    Console.Error.WriteLine($"Using sandbox: {etradeConfig.UseSandbox}");

    // Load the E*TRADE OpenAPI spec from embedded resource
    var openApiSpecPath = Path.Combine(AppContext.BaseDirectory, "etrade-api.yaml");
    
    if (!File.Exists(openApiSpecPath))
    {
        Console.Error.WriteLine($"OpenAPI spec file not found: {openApiSpecPath}");
        return 1;
    }

    var openApiSpec = await File.ReadAllTextAsync(openApiSpecPath);
    Console.Error.WriteLine("E*TRADE OpenAPI spec loaded successfully");

    // Build the MCP server - pass empty args to avoid parsing URL as host args
    var builder = Host.CreateApplicationBuilder(Array.Empty<string>());

    // IMPORTANT: Disable default console logging - it writes to stdout which breaks MCP protocol!
    builder.Logging.ClearProviders();

    var logPath = Path.Combine(AppContext.BaseDirectory, "EtradeMcpServer.log");

    Console.Error.WriteLine("logPath: " + logPath);

    builder.Services.AddSerilog(new LoggerConfiguration()
        .MinimumLevel.Warning()
        .WriteTo.File(logPath)
        .CreateLogger());

    Console.Error.WriteLine("Configuring MCP server...");

    using var tokenStore = new EncryptedFileTokenStore(etradeConfig);
    using var oauthClient = new HttpClient(new ReadOnlyGuard(etradeConfig, true)
        { InnerHandler = new HttpClientHandler { AllowAutoRedirect = false } })
        { Timeout = TimeSpan.FromSeconds(etradeConfig.TimeoutSeconds) };
    var authHandler = new EtradeOAuth1AuthenticationHandler(oauthClient, etradeConfig, tokenStore);
    await authHandler.InitializeAsync();
    using var httpClient = new HttpClient(new ReadOnlyGuard(etradeConfig, false, authHandler)
        { InnerHandler = new HttpClientHandler { AllowAutoRedirect = false } })
        { BaseAddress = new Uri(etradeConfig.BaseUrl), Timeout = TimeSpan.FromSeconds(etradeConfig.TimeoutSeconds) };
    var oauthSession = authHandler.Session;
    var oauthTools = new EtradeOAuthMcpTools(authHandler);

    builder.Services
        .AddMcpServer()
        .WithStdioServerTransport()
        // Register E*TRADE OAuth tools for interactive authentication
        .WithTools(oauthTools)
        // Register API tools from OpenAPI spec
        .WithToolsFromOpenApi(ReadOnlyPolicy.Filter(openApiSpec), etradeConfig.BaseUrl)
        .Services
        .AddSingleton(etradeConfig)
        .AddSingleton(httpClient)
        .AddSingleton(authHandler)
        .AddSingleton<IAuthenticationHandler>(authHandler)
        .AddSingleton(oauthSession)
        .AddSingleton(oauthTools);

    var app = builder.Build();

    await app.RunAsync();

    Console.Error.WriteLine("E*TRADE MCP Server ready. Listening on stdio...");

    return 0;
}
catch (Exception)
{
    Console.Error.WriteLine("E*TRADE MCP startup failed. Check storage permissions, key, lock, and configuration; no credentials were exposed.");
    return 1;
}