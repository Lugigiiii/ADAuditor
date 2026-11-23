namespace ADAudit.Shared;

/// <summary>
/// Automatic background changes that are not something a person did in AD:
///  • computers maintaining their own attributes (SPNs, DNS host name, OS version, encryption types, certificate …)
///  • dynamic DNS record updates written by computers / the system
/// Security-relevant self-writes (delegation, key credentials, account flags) are never treated as noise.
/// </summary>
public static class Noise
{
    public static readonly string[] SelfMaintainedAttributes =
    {
        "servicePrincipalName", "dNSHostName", "msDS-AdditionalDnsHostName", "msDS-AdditionalSamAccountName",
        "msDS-SupportedEncryptionTypes", "operatingSystem", "operatingSystemVersion", "operatingSystemServicePack",
        "operatingSystemHotfix", "userCertificate", "networkAddress", "msDS-isGC", "msDS-isRODC", "description",
        "msTPM-TpmInformationForComputer", "msDS-DeviceLocation",
    };

    static readonly HashSet<string> SelfSet = new(SelfMaintainedAttributes, StringComparer.OrdinalIgnoreCase);

    static bool IsMachineActor(AuditEntry e) =>
        e.Actor.EndsWith("(computer)", StringComparison.OrdinalIgnoreCase) || e.Actor.StartsWith("SYSTEM (", StringComparison.OrdinalIgnoreCase) || e.IsReconstructed;

    public static bool IsNoise(AuditEntry e)
    {
        if (e.IsNoOp) return true;
        if (e.TargetClass.Equals("dnsNode", StringComparison.OrdinalIgnoreCase) && IsMachineActor(e)) return true;
        if (e.Category != Cat.Modify || !SelfSet.Contains(e.Attribute)) return false;
        // reconstructed: actor unknown, but these attributes on computer objects are maintained by the computer itself
        if (e.IsReconstructed && e.TargetClass.Equals("computer", StringComparison.OrdinalIgnoreCase)
            && !e.Attribute.Equals("description", StringComparison.OrdinalIgnoreCase)) return true;
        // "CORP\PC042$ (computer)" changing CN=PC042,…
        if (e.Actor.EndsWith("$ (computer)", StringComparison.OrdinalIgnoreCase))
        {
            var name = e.Actor[..e.Actor.LastIndexOf('$')];
            name = name[(name.LastIndexOf('\\') + 1)..];
            return Dn.FriendlyName(e.TargetDn).Equals(name, StringComparison.OrdinalIgnoreCase);
        }
        return false;
    }

    /// <summary>The same rule as SQL, to hide noise that was stored before the filter existed.</summary>
    public static string Sql(string a = "a") => $"""
        NOT (
          ({a}.category='Modify' AND {a}.old_value<>'' AND {a}.old_value={a}.new_value)
          OR ({a}.target_class='dnsNode' AND ({a}.actor LIKE '%(computer)' OR {a}.actor LIKE 'SYSTEM (%' OR {a}.event_id=-1))
          OR ({a}.category='Modify' AND {a}.attribute IN ({string.Join(",", SelfMaintainedAttributes.Select(s => $"'{s}'"))}) AND (
               ({a}.event_id=-1 AND {a}.target_class='computer' AND {a}.attribute<>'description')
            OR ({a}.actor LIKE '%$ (computer)' AND instr({a}.target_dn, ',') > 4
                AND instr(lower({a}.actor), '\' || lower(substr({a}.target_dn, 4, instr({a}.target_dn, ',') - 4)) || '$') > 0)))
        )
        """;
}
