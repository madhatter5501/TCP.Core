namespace TCP.L5_7.Application.Http2;

/// <summary>One 6-byte identifier/value pair from a SETTINGS frame.</summary>
/// <param name="Id">The parameter; may be a value outside <see cref="Http2SettingId"/>, which receivers ignore.</param>
/// <param name="Value">The parameter's new value.</param>
public readonly record struct Http2Setting(Http2SettingId Id, uint Value)
{
    public override string ToString() => $"{Id}={Value}";
}
