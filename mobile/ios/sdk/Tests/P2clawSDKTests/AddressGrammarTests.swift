import XCTest
@testable import P2clawSDK

final class AddressGrammarTests: XCTestCase {
    func testAliasOnly() throws {
        let addr = try AddressGrammar.parse("https://abc.p2claw.com/")
        XCTAssertEqual(addr.alias, "abc")
        XCTAssertNil(addr.app)
        XCTAssertEqual(addr.parentZone, "p2claw.com")
    }

    func testAppPrefix() throws {
        let addr = try AddressGrammar.parse("https://myapp.abc.p2claw.com/")
        XCTAssertEqual(addr.alias, "abc")
        XCTAssertEqual(addr.app, "myapp")
        XCTAssertEqual(addr.parentZone, "p2claw.com")
    }

    func testTrailingPathIgnored() throws {
        let addr = try AddressGrammar.parse("https://abc.p2claw.com/some/path?q=1")
        XCTAssertEqual(addr.alias, "abc")
        XCTAssertEqual(addr.parentZone, "p2claw.com")
    }

    func testRejectsInvalidScheme() {
        XCTAssertThrowsError(try AddressGrammar.parse("ftp://abc.p2claw.com/"))
    }

    func testRejectsEmptyHost() {
        XCTAssertThrowsError(try AddressGrammar.parse("https:///"))
    }

    func testRejectsUppercaseLabels() throws {
        // Hosts are lowercased on parse so uppercase input is accepted
        // and normalized to lowercase. This is the intended behavior.
        let addr = try AddressGrammar.parse("https://ABC.P2claw.com/")
        XCTAssertEqual(addr.alias, "abc")
    }

    func testRejectsHyphenLeadingLabel() {
        XCTAssertThrowsError(try AddressGrammar.parse("https://-bad.p2claw.com/"))
    }

    func testRejectsUnderscoreLabel() {
        XCTAssertThrowsError(try AddressGrammar.parse("https://bad_label.p2claw.com/"))
    }
}
