import XCTest
@testable import P2clawSDK

final class ResponseTests: XCTestCase {
    func testHeaderCaseInsensitiveLookup() {
        let r = Response(
            status: 200,
            headers: [
                ("Content-Type", "text/plain"),
                ("X-Custom", "v1"),
            ],
            body: Data()
        )
        XCTAssertEqual(r.header("content-type"), "text/plain")
        XCTAssertEqual(r.header("X-CUSTOM"), "v1")
        XCTAssertNil(r.header("absent"))
    }

    func testHeaderReturnsFirstMatchOnDuplicates() {
        let r = Response(
            status: 200,
            headers: [
                ("Set-Cookie", "a=1"),
                ("Set-Cookie", "b=2"),
            ],
            body: Data()
        )
        XCTAssertEqual(r.header("set-cookie"), "a=1")
    }
}
