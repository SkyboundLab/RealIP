package net.tcpshield.tcpshield.util.validation.cidr;

import net.tcpshield.tcpshield.TCPShieldPlugin;
import net.tcpshield.tcpshield.util.exception.phase.CIDRException;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Validates source IPs against a whitelist folder of CIDR .list files.
 */
public class CIDRValidator {

	private final TCPShieldPlugin plugin;

	private final File whitelistFolder;

	private final List<CIDRMatcher> cidrMatchers;
	private final Set<String> cache = ConcurrentHashMap.newKeySet(); // Max potential size is equilivent to the amount of whitelisted IP's

	private volatile List<CIDRMatcher> remoteMatchers = List.of();

	public void setRemoteMatchers(List<CIDRMatcher> remoteMatchers) {
		this.remoteMatchers = List.copyOf(remoteMatchers);
		cache.clear();
	}

	public CIDRValidator(TCPShieldPlugin plugin) throws CIDRException {
		this(plugin, "ip-whitelist", "local-network.list");
	}

	public CIDRValidator(TCPShieldPlugin plugin, String folderName, String... bundledDefaults) throws CIDRException {
		this.plugin = plugin;

		whitelistFolder = new File(plugin.getConfigProvider().getDataFolder(), folderName);
		if (!whitelistFolder.exists())
			whitelistFolder.mkdir();

		try {
			installBundledDefaults(folderName, bundledDefaults);
			List<String> whitelists = loadWhitelists();
			cidrMatchers = loadCIDRMatchers(whitelists);
		} catch (Exception e) {
			throw new CIDRException(e);
		}
	}

	private void installBundledDefaults(String folderName, String... bundledDefaults) throws IOException {
		for (String fileName : bundledDefaults) {
			File target = new File(whitelistFolder, fileName);
			if (target.exists())
				continue;

			try (InputStream in = getClass().getResourceAsStream("/" + folderName + "/" + fileName)) {
				if (in == null) {
					plugin.getDebugger().warn("Bundled default list \"/%s/%s\" is missing from the jar, skipping it.", folderName, fileName);
					continue;
				}
				Files.copy(in, target.toPath(), StandardCopyOption.REPLACE_EXISTING);
				plugin.getDebugger().warn("Installed default list \"%s/%s\". Edit it to change which IPs are allowed.", folderName, fileName);
			}
		}
	}

	private List<CIDRMatcher> loadCIDRMatchers(List<String> whitelists) {
		List<CIDRMatcher> matchers = new ArrayList<>();

		for (String whitelist : whitelists)
			try {
				matchers.add(CIDRMatcher.create(whitelist));
			} catch (Exception e) {
				plugin.getDebugger().warn("Exception occured while creating CIDRMatcher for \"%s\". Ignoring it.", whitelist);
				plugin.getDebugger().exception(e);
			}

		return matchers;
	}

	private List<String> loadWhitelists() throws FileNotFoundException {
		List<String> whitelists = new ArrayList<>();

		for (File file : Objects.requireNonNull(whitelistFolder.listFiles())) {
			if (file.isDirectory())
				continue;

			try (Scanner scanner = new Scanner(file)) {
				while (scanner.hasNextLine()) {
					String cidrEntry = scanner.nextLine().trim();
					if (cidrEntry.isEmpty() || cidrEntry.startsWith("#"))
						continue;
					whitelists.add(cidrEntry);
				}
			}
		}

		return whitelists;
	}

	/**
	 * Validates an InetAddress with CIDR matchers
	 * @param inetAddress The InetAddress to validate
	 * @return Boolean stating if the InetAddress is validated with CIDR
	 */
	public boolean validate(InetAddress inetAddress) {
		String ip = inetAddress.getHostAddress();

		if (cache.contains(ip))
			return true;

		for (CIDRMatcher cidrMatcher : cidrMatchers)
			if (cidrMatcher.match(inetAddress)) {
				cache.add(ip);
				return true;
			}

		for (CIDRMatcher cidrMatcher : remoteMatchers)
			if (cidrMatcher.match(inetAddress)) {
				cache.add(ip);
				return true;
			}

		return false;
	}

}
