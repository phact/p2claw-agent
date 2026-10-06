import Foundation

/// Parsed `[app.]alias.<parent>` shape extracted from a box URL.
struct BoxAddress: Equatable, Sendable {
    let alias: String
    let app: String?
    /// Full parent zone — everything past the alias label. The coord
    /// URL is derived from this by prepending `coord.` unless the
    /// caller overrode it on `P2clawClient`.
    let parentZone: String
}

enum AddressGrammar {
    /// Parse a URL like `https://abc.p2claw.com/` or
    /// `https://myapp.abc.p2claw.com/` into its alias / app / parent
    /// components.
    ///
    /// Throws `P2clawError.invalidBoxUrl` on any of: scheme not http(s),
    /// host missing, fewer than two host labels, label characters
    /// outside `[a-z0-9-]`.
    static func parse(_ raw: String) throws -> BoxAddress {
        guard let url = URL(string: raw),
              let scheme = url.scheme?.lowercased(),
              scheme == "https" || scheme == "http",
              let host = url.host?.lowercased()
        else {
            throw P2clawError.invalidBoxUrl(raw)
        }
        let labels = host.split(separator: ".").map(String.init)
        guard labels.count >= 2 else {
            throw P2clawError.invalidBoxUrl(raw)
        }
        for label in labels {
            guard isValidLabel(label) else {
                throw P2clawError.invalidBoxUrl(raw)
            }
        }
        if labels.count == 2 {
            // `alias.parent` is the smallest valid shape; parent zone
            // collapses to the last label alone. Edge case used in
            // tests against `localhost`-style single-zone setups.
            return BoxAddress(alias: labels[0], app: nil, parentZone: labels[1])
        }
        // Three or more labels: the first is the app and the second
        // the alias; everything after is the parent zone.
        if labels.count >= 3 {
            return BoxAddress(
                alias: labels[1],
                app: labels[0],
                parentZone: labels.dropFirst(2).joined(separator: ".")
            )
        }
        throw P2clawError.invalidBoxUrl(raw)
    }

    private static func isValidLabel(_ s: String) -> Bool {
        guard !s.isEmpty, s.count <= 63 else { return false }
        for c in s.unicodeScalars {
            let ok = (c.value >= 0x61 && c.value <= 0x7A)  // a-z
                || (c.value >= 0x30 && c.value <= 0x39)    // 0-9
                || c.value == 0x2D                          // -
            if !ok { return false }
        }
        // Per RFC 1035: labels can't start or end with hyphen.
        if s.first == "-" || s.last == "-" { return false }
        return true
    }
}
