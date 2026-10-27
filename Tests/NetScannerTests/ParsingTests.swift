import XCTest
@testable import NetScanner

final class TargetParserTests: XCTestCase {
    func testCIDRSkipsNetworkAndBroadcast() throws {
        let ips = try TargetParser.parse("192.168.1.0/30")
        XCTAssertEqual(ips.map(\.description), ["192.168.1.1", "192.168.1.2"])
    }

    func testSlash24Count() throws {
        XCTAssertEqual(try TargetParser.parse("10.0.0.77/24").count, 254)
    }

    func testSlash32() throws {
        XCTAssertEqual(try TargetParser.parse("10.1.2.3/32").map(\.description), ["10.1.2.3"])
    }

    func testShortRange() throws {
        let ips = try TargetParser.parse("10.0.0.250-254")
        XCTAssertEqual(ips.first?.description, "10.0.0.250")
        XCTAssertEqual(ips.count, 5)
    }

    func testFullRangeListAndDedup() throws {
        let ips = try TargetParser.parse("10.0.0.1-10.0.0.3, 10.0.0.2; 10.0.0.9")
        XCTAssertEqual(ips.map(\.description), ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.9"])
    }

    func testRejectsGarbageAndHuge() {
        XCTAssertThrowsError(try TargetParser.parse("10.0.0.0/8"))
        XCTAssertThrowsError(try TargetParser.parse("300.1.1.1"))
        XCTAssertThrowsError(try TargetParser.parse("10.0.0.9-3"))
        XCTAssertThrowsError(try TargetParser.parse("   "))
    }
}

final class PortSpecTests: XCTestCase {
    func testParse() throws {
        XCTAssertEqual(try PortSpec.parse("22, 80-82,80"), [22, 80, 81, 82])
        XCTAssertThrowsError(try PortSpec.parse("0"))
        XCTAssertThrowsError(try PortSpec.parse("70000"))
        XCTAssertThrowsError(try PortSpec.parse("100-10"))
    }

    func testTopPortsMatchNmap() throws {
        XCTAssertEqual(try PortSpec.parse(PortData.top100).count, 100)
        XCTAssertEqual(try PortSpec.parse(PortData.top1000).count, 1000)
    }

    func testServiceNames() {
        XCTAssertEqual(ServiceDB.name(for: 22), "ssh")
        XCTAssertEqual(ServiceDB.name(for: 3389), "rdp")
        XCTAssertEqual(ServiceDB.name(for: 1), "tcpmux")
    }
}

final class ProtocolParsingTests: XCTestCase {
    func testMACNormalize() {
        XCTAssertEqual(MAC.normalize("a4:2b:b0:1:2:3"), "A4:2B:B0:01:02:03")
        XCTAssertNil(MAC.normalize("ff:ff:ff:ff:ff:ff"))
        XCTAssertNil(MAC.normalize("(incomplete)"))
        XCTAssertTrue(MAC.isRandomized("DA:A1:19:00:00:01"))
        XCTAssertFalse(MAC.isRandomized("A4:2B:B0:00:00:01"))
    }

    func testARPParse() {
        let out = """
        ? (192.168.1.1) at a4:2b:b0:1:2:3 on en0 ifscope [ethernet]
        ? (192.168.1.7) at (incomplete) on en0 ifscope [ethernet]
        ? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
        """
        let map = ARPTable.parse(out)
        XCTAssertEqual(map.count, 1)
        XCTAssertEqual(map[IPv4("192.168.1.1")!.raw], "A4:2B:B0:01:02:03")
    }

    func testICMPChecksumVerifies() {
        let pkt = ICMPPinger.packet(id: 0x1234, seq: 7)
        XCTAssertEqual(ICMPPinger.checksum(pkt), 0, "checksum over a valid packet must be 0")
        XCTAssertTrue(ICMPPinger.isEchoReply([0, 0, 0, 0, 0, 0, 0, 0]))
        // With a 20-byte IPv4 header in front:
        XCTAssertTrue(ICMPPinger.isEchoReply([0x45] + Array(repeating: 0, count: 19) + [0, 0, 0, 0, 0, 0, 0, 0]))
        XCTAssertFalse(ICMPPinger.isEchoReply([8, 0, 0, 0, 0, 0, 0, 0]))
    }

    func testDNSPTRWithCompression() {
        let qname = DNSMessage.encodeName("4.3.2.1.in-addr.arpa")
        var m: [UInt8] = [0x12, 0x34, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0]  // QD=0 AN=1
        m += qname                                   // owner name at offset 12
        m += [0, 12, 0, 1, 0, 0, 0, 120]             // TYPE=PTR CLASS=IN TTL
        let rdata: [UInt8] = Array(DNSMessage.encodeName("iphone").dropLast()) + [0xC0, 12]  // "iphone" + pointer
        m += [0, UInt8(rdata.count)]
        m += rdata
        XCTAssertEqual(DNSMessage.firstPTR(m), "iphone.4.3.2.1.in-addr.arpa")

        var plain: [UInt8] = [0, 1, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0]
        plain += qname + [0, 12, 0, 1, 0, 0, 0, 120]
        let host = DNSMessage.encodeName("MacBook-Pro.local")
        plain += [0, UInt8(host.count)] + host
        XCTAssertEqual(DNSMessage.firstPTR(plain), "MacBook-Pro.local")
    }

    func testNetBIOSParse() {
        func entry(_ name: String, _ suffix: UInt8, group: Bool) -> [UInt8] {
            var b = Array(name.utf8.prefix(15))
            b += Array(repeating: 0x20, count: 15 - b.count)
            return b + [suffix, group ? 0x84 : 0x04, 0x00]
        }
        var m: [UInt8] = [0xAB, 0xCD, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0]
        m += [0x20] + Array("CK".utf8) + Array(repeating: UInt8(ascii: "A"), count: 30) + [0]
        m += [0x00, 0x21, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x00]  // TYPE CLASS TTL RDLEN
        m += [3]
        m += entry("DESKTOP-42", 0x00, group: false)
        m += entry("WORKGROUP", 0x00, group: true)
        m += entry("DESKTOP-42", 0x20, group: false)
        m += [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        let info = NameResolver.parseNetBIOS(m)
        XCTAssertEqual(info?.name, "DESKTOP-42")
        XCTAssertEqual(info?.group, "WORKGROUP")
        XCTAssertEqual(info?.mac, "00:11:22:33:44:55")
    }

    func testServiceClassify() {
        let ssh = ServiceProbe.classify(Array("SSH-2.0-OpenSSH_9.6\r\n".utf8), port: 2222)
        XCTAssertEqual(ssh, .init(service: "ssh", banner: "SSH-2.0-OpenSSH_9.6"))

        let http = ServiceProbe.classify(Array("HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\n".utf8), port: 8080)
        XCTAssertEqual(http.service, "http")
        XCTAssertEqual(http.banner, "nginx/1.25.3 · HTTP/1.1 200 OK")

        let mysqlGreeting: [UInt8] = [0x4A, 0, 0, 0, 0x0A] + Array("8.0.36".utf8) + [0, 1, 2, 3]
        XCTAssertEqual(ServiceProbe.classify(mysqlGreeting, port: 3306).banner, "MySQL 8.0.36")
    }

    func testOUIParseFormats() {
        let text = """
        Registry,Assignment,Organization Name,Organization Address
        MA-L,286FB9,"Nokia Shanghai Bell Co., Ltd.",No.388 Ning Qiao Road
        A42BB0 TP-LINK TECHNOLOGIES CO.,LTD.
        3C2EF9\tApple, Inc.
        """
        let m = OUIDatabase.parse(text)
        XCTAssertEqual(m[0x286FB9], "Nokia Shanghai Bell Co., Ltd.")
        XCTAssertEqual(m[0xA42BB0], "TP-LINK TECHNOLOGIES CO.,LTD.")
        XCTAssertEqual(m[0x3C2EF9], "Apple, Inc.")
        XCTAssertEqual(m.count, 3)
    }
}
