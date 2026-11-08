package net.tcpshield.tcpshield.util.validation.cidr;

import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Guards the IP allowlists shipped in the jar: every entry must parse, the
 * TCPShield ranges must match real edge IPs (and nothing else), the local
 * list must match the LAN, and the two lists must not overlap in a way that
 * would let a TCPShield IP connect directly or a LAN IP pose as a proxy.
 */
public class IPAllowlistTest {

	private static List<CIDRMatcher> loadShippedList(String resourcePath) throws Exception {
		try (InputStream in = IPAllowlistTest.class.getResourceAsStream(resourcePath)) {
			assertNotNull(in, "Shipped list missing from jar: " + resourcePath);
			List<String> lines;
			try (BufferedReader reader = new BufferedReader(new InputStreamReader(in))) {
				lines = reader.lines().collect(Collectors.toList());
			}
			List<CIDRMatcher> matchers = new ArrayList<>();
			for (String line : lines) {
				String entry = line.trim();
				if (entry.isEmpty() || entry.startsWith("#"))
					continue;
				matchers.add(CIDRMatcher.create(entry)); // throws on a typo'd entry
			}
			assertFalse(matchers.isEmpty(), "Shipped list is empty: " + resourcePath);
			return matchers;
		}
	}

	private static boolean matchesAny(List<CIDRMatcher> matchers, String address) throws Exception {
		InetAddress inetAddress = InetAddress.getByName(address);
		for (CIDRMatcher matcher : matchers)
			if (matcher.match(inetAddress))
				return true;
		return false;
	}

	@Test
	public void proxyListMatchesTCPShieldEdges() throws Exception {
		List<CIDRMatcher> proxy = loadShippedList("/proxy-whitelist/tcpshield-ips.list");

		// tcpshield.com/v4/
		assertTrue(matchesAny(proxy, "198.178.119.1"));
		assertTrue(matchesAny(proxy, "198.178.119.254"));
		assertTrue(matchesAny(proxy, "104.234.6.1"));
		assertTrue(matchesAny(proxy, "104.234.6.127")); // top of the /25

		// tcpshield.com/v4-cf/ (/31s and /30s)
		assertTrue(matchesAny(proxy, "89.222.122.36"));
		assertTrue(matchesAny(proxy, "89.222.122.37"));
		assertTrue(matchesAny(proxy, "5.135.84.92"));
		assertTrue(matchesAny(proxy, "5.135.84.95")); // top of the /30
		assertTrue(matchesAny(proxy, "203.205.31.160"));
		assertTrue(matchesAny(proxy, "203.205.31.161"));

		// TCPShield AS64199 IPv6
		assertTrue(matchesAny(proxy, "2602:fa78::1"));
		assertTrue(matchesAny(proxy, "2602:fa78:ff:ffff::1"));
	}

	@Test
	public void proxyListRejectsEverythingElse() throws Exception {
		List<CIDRMatcher> proxy = loadShippedList("/proxy-whitelist/tcpshield-ips.list");

		assertFalse(matchesAny(proxy, "104.234.6.128")); // just outside the /25
		assertFalse(matchesAny(proxy, "104.234.6.200"));
		assertFalse(matchesAny(proxy, "198.178.120.1"));
		assertFalse(matchesAny(proxy, "89.222.122.38")); // just outside the /31
		assertFalse(matchesAny(proxy, "5.135.84.96")); // just outside the /30
		assertFalse(matchesAny(proxy, "1.2.3.4"));
		assertFalse(matchesAny(proxy, "8.8.8.8"));
		assertFalse(matchesAny(proxy, "2602:fa79::1")); // just outside the /40
		// A LAN IP must never count as a proxy source
		assertFalse(matchesAny(proxy, "192.168.2.50"));
		assertFalse(matchesAny(proxy, "127.0.0.1"));
	}

	@Test
	public void directListMatchesLocalNetwork() throws Exception {
		List<CIDRMatcher> direct = loadShippedList("/ip-whitelist/local-network.list");

		assertTrue(matchesAny(direct, "192.168.2.1"));
		assertTrue(matchesAny(direct, "192.168.2.254"));
		assertTrue(matchesAny(direct, "127.0.0.1"));
		assertTrue(matchesAny(direct, "::1"));
		// Dual-stack servers can see a LAN peer as an IPv4-mapped IPv6 address
		assertTrue(matchesAny(direct, "::ffff:192.168.2.50"));
		assertTrue(matchesAny(direct, "::ffff:127.0.0.1"));
	}

	@Test
	public void directListRejectsEverythingElse() throws Exception {
		List<CIDRMatcher> direct = loadShippedList("/ip-whitelist/local-network.list");

		assertFalse(matchesAny(direct, "192.168.3.1"));
		assertFalse(matchesAny(direct, "192.168.1.50"));
		assertFalse(matchesAny(direct, "10.0.0.5"));
		assertFalse(matchesAny(direct, "8.8.8.8"));
		// A TCPShield IP must never get direct (no-handshake) access
		assertFalse(matchesAny(direct, "198.178.119.1"));
		assertFalse(matchesAny(direct, "104.234.6.1"));
	}

	@Test
	public void ipv4MappedIPv6MatchesItsIPv4CIDR() throws Exception {
		assertTrue(CIDRMatcher.create("192.168.2.0/24").match(InetAddress.getByName("::ffff:192.168.2.50")));
		assertFalse(CIDRMatcher.create("192.168.2.0/24").match(InetAddress.getByName("::ffff:192.168.3.50")));
		assertTrue(CIDRMatcher.create("203.0.113.7").match(InetAddress.getByName("::ffff:203.0.113.7")));
		assertFalse(CIDRMatcher.create("203.0.113.7").match(InetAddress.getByName("::ffff:203.0.113.8")));
	}
}
