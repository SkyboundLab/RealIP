package net.tcpshield.tcpshield.util.validation.cidr;

import net.tcpshield.tcpshield.util.exception.phase.CIDRException;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

/**
 * CIDR matcher for the CIDR validator
 */
public abstract class CIDRMatcher {

	/**
	 * Creates a CIDRMatcher from a CIDR matching regex
	 * @param cidrMatchString The string containing the CIDR matching regex
	 * @return The corrosponding CIDRMatcher
	 */
	public static CIDRMatcher create(String cidrMatchString) {
		return new CIDRMatcher(cidrMatchString) {
			@Override
			public boolean match(InetAddress inetAddress) {
				return super.match(inetAddress);
			}
		};
	}


	private final int maskBits;
	private final int maskBytes;
	private final boolean simpleCIDR;
	private final InetAddress cidrAddress;

	private CIDRMatcher(String cidrMatchString) {
		String[] split = cidrMatchString.split("/");

		String parsedIPAddress;
		if (split.length > 1) {
			parsedIPAddress = split[0];

			this.maskBits = Integer.parseInt(split[1]);
			if (maskBits < 0)
				throw new CIDRException("Invalid mask: " + split[1]);
		} else {
			parsedIPAddress = cidrMatchString;

			this.maskBits = -1;
		}

		if (parsedIPAddress.isEmpty())
			throw new CIDRException("Empty CIDR entry");

		try {
			cidrAddress = unwrapIPv4Mapped(InetAddress.getByName(parsedIPAddress));
		} catch (UnknownHostException e) {
			throw new CIDRException(e);
		}

		int addressBits = cidrAddress.getAddress().length * 8;
		if (maskBits > addressBits)
			throw new CIDRException("Invalid mask: " + maskBits + " is longer than the " + addressBits + " bit address " + parsedIPAddress);

		this.simpleCIDR = maskBits == -1 || maskBits == addressBits;
		this.maskBytes = simpleCIDR ? -1 : maskBits / 8;
	}

	/**
	 * Unwraps an IPv4-mapped IPv6 address ({@code ::ffff:a.b.c.d}) to its plain
	 * IPv4 form. On dual-stack servers a TCP peer that connected over IPv4
	 * can show up as a mapped IPv6 address; without this, an IPv4 CIDR such
	 * as {@code 192.168.2.0/24} would never match it and legitimate
	 * connections would be rejected.
	 */
	private static InetAddress unwrapIPv4Mapped(InetAddress address) {
		byte[] bytes = address.getAddress();
		if (bytes.length != 16)
			return address;

		for (int i = 0; i < 10; i++)
			if (bytes[i] != 0)
				return address;
		if (bytes[10] != (byte) 0xFF || bytes[11] != (byte) 0xFF)
			return address;

		try {
			return InetAddress.getByAddress(Arrays.copyOfRange(bytes, 12, 16));
		} catch (UnknownHostException e) {
			return address;
		}
	}

	/**
	 * Compares the provided InetAddress with the CIDR for a match
	 * @param inetAddress The InetAddress to match with the CIDR
	 * @return Boolean stating if the provided InetAddress matches the CIDR
	 */
	public boolean match(InetAddress inetAddress) {
		inetAddress = unwrapIPv4Mapped(inetAddress);

		if (!cidrAddress.getClass().equals(inetAddress.getClass())) return false; // check if IP is IPv4 or IPv6

		if (simpleCIDR) return inetAddress.equals(cidrAddress); // check for equality if it's a simple CIDR

		byte[] inetAddressBytes = inetAddress.getAddress();
		byte[] requiredAddressBytes = cidrAddress.getAddress();

		byte finalByte = (byte) (0xFF00 >> (maskBits & 0x07));

		for (int i = 0; i < maskBytes; i++) {
			if (inetAddressBytes[i] != requiredAddressBytes[i]) return false;
		}

		if (finalByte != 0)
			return (inetAddressBytes[maskBytes] & finalByte) == (requiredAddressBytes[maskBytes] & finalByte);

		return true;
	}

}
