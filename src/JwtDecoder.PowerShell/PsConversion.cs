using System.Management.Automation;
using System.Text.Json;

namespace JwtDecoder.PowerShell;

/// <summary>
/// Converts <see cref="JsonElement"/> trees into PowerShell-friendly object graphs:
/// objects become <see cref="PSObject"/> with note properties (dot-accessible in PS),
/// arrays become <c>object?[]</c>, and primitive types map to their .NET equivalents.
/// </summary>
internal static class PsConversion
{
    public static PSObject ToPSObject(JsonElement element)
    {
        var ps = new PSObject();
        if (element.ValueKind != JsonValueKind.Object)
        {
            ps.Properties.Add(new PSNoteProperty("Value", ToValue(element)));
            return ps;
        }

        foreach (var prop in element.EnumerateObject())
        {
            ps.Properties.Add(new PSNoteProperty(prop.Name, ToValue(prop.Value)));
        }
        return ps;
    }

    public static object? ToValue(JsonElement el)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.String: return el.GetString();
            case JsonValueKind.True:   return true;
            case JsonValueKind.False:  return false;
            case JsonValueKind.Null:   return null;
            case JsonValueKind.Number:
                if (el.TryGetInt64(out long l)) return l;
                if (el.TryGetDouble(out double d)) return d;
                return el.GetRawText();
            case JsonValueKind.Object:
                return ToPSObject(el);
            case JsonValueKind.Array:
                var arr = new List<object?>();
                foreach (var item in el.EnumerateArray()) arr.Add(ToValue(item));
                return arr.ToArray();
            default:
                return el.GetRawText();
        }
    }
}
