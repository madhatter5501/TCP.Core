namespace TCP.Explorer;

/// <summary>Which transport is serving this Explorer instance, reported to the page.</summary>
public sealed record ExplorerTransportInfo(string Mode, string Endpoint);

/// <summary>The Explorer's routes and static files, shared by the app and the transport tests.</summary>
public static class ExplorerEndpoints
{
    public const string SimulateRoute = "/api/simulate";
    public const string TransportRoute = "/api/transport";

    public static WebApplication MapExplorer(this WebApplication app, ExplorerTransportInfo transport)
    {
        app.MapGet(TransportRoute, () => Results.Ok(transport));
        app.MapPost(SimulateRoute, (SimulationRequest request) =>
        {
            try { return Results.Ok(TransmissionSimulation.Run(request)); }
            catch (ArgumentException error) { return Results.BadRequest(new { error = error.Message }); }
        });
        app.UseDefaultFiles();
        app.UseStaticFiles();
        // Client-side routes such as /layers/network/gotchas load the app shell. Missing files and unknown /api paths stay 404s.
        app.MapFallbackToFile("{*path:nonfile:regex(^(?!api/).*$)}", "index.html");
        return app;
    }
}
