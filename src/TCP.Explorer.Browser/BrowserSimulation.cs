using System.Runtime.InteropServices.JavaScript;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TCP.Explorer;

/// <summary>
/// The browser entry point for <see cref="TransmissionSimulation"/>. It takes and returns the same JSON as
/// POST /api/simulate, so the UI renders either source unchanged.
/// </summary>
[SupportedOSPlatform("browser")]
public static partial class BrowserSimulation
{
    public static void Main() { }

    /// <summary>Runs one experiment. Invalid input returns <c>{ "error": "…" }</c>, as the API's 400 response does.</summary>
    [JSExport]
    public static string Simulate(string requestJson)
    {
        var request = JsonSerializer.Deserialize(requestJson, SimulationJson.Default.SimulationRequest)
            ?? throw new ArgumentException("Send a simulation request.");
        try { return JsonSerializer.Serialize(TransmissionSimulation.Run(request), SimulationJson.Default.SimulationResult); }
        catch (ArgumentException error) { return JsonSerializer.Serialize(new SimulationError(error.Message), SimulationJson.Default.SimulationError); }
    }
}

public sealed record SimulationError(string Error);

// ASP.NET's web defaults: camelCase names, case-insensitive reads.
[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(SimulationRequest))]
[JsonSerializable(typeof(SimulationResult))]
[JsonSerializable(typeof(SimulationError))]
internal sealed partial class SimulationJson : JsonSerializerContext;
