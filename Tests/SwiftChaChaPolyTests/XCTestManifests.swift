import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
    return [
        testCase(SwiftChaChaPolyTests.allTests),
    ]
}
#endif
