import Foundation

/// HTTP response returned by `Connection.fetch`.
public struct Response: Sendable {
    public let status: UInt16
    /// Preserves duplicate header keys in arrival order.
    public let headers: [(String, String)]
    public let body: Data

    public init(status: UInt16, headers: [(String, String)], body: Data) {
        self.status = status
        self.headers = headers
        self.body = body
    }

    /// Find the first header matching `name` (case-insensitive).
    public func header(_ name: String) -> String? {
        let lower = name.lowercased()
        return headers.first { $0.0.lowercased() == lower }?.1
    }
}
