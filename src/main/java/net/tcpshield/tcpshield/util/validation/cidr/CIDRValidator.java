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
 * A CIDR validator for TCPShield.
 *
 * Each instance guards one list folder under the plugin data folder:
 * <ul>
 *   <li>{@code ip-whitelist} - sources allowed to connect directly, without a
 *   TCPShield handshake (local / private networks).</li>
 *   <li>{@code proxy-whitelist} - sources allowed to present a signed
 *   TCPShield handshake (TCPShield edge IPs).</li>
 * </ul>
 * On first use, bundled default files shipped inside the jar are copied into
 * the folder when missing, so a fresh install works out of the box while
 * user edits are never overwritten.
 */
public class CIDRValidator {

	private final TCPShieldPlugin plugin;

	private final File whitelistFolder;

	private final List<CIDRMatcher> cidrMatchers;
	private final Set<String> cache = ConcurrentHashMap.newKeySet(); // Max potential size is equilivent to the amount of whitelisted IP's

	// Ranges supplied by an outside source (e.g. fetched from TCPShield),
	// swapped atomically when they refresh. File ranges above are static.
	private volatile List<CIDRMatcher> remoteMatchers = List.of();

	/**
	 * Replaces the remotely supplied ranges. The positive cache is cleared
	 * with it: a range that was removed must stop matching, even for an IP
	 * that matched before the refresh.
	 */
	public void setRemoteMatchers(List<CIDRMatcher> remoteMatchers) {
		this.remoteMatchers = List.copyOf(remoteMatchers);
		cache.clear();
	}

	public CIDRValidator(TCPShieldPlugin plugin) throws CIDRException {
		this(plugin, "ip-whitelist", "local-network.list");
	}

	/**
	 * Creates a validator for one list folder.
	 *
	 * @param plugin The TCPShield plugin
	 * @param folderName The folder under the plugin data folder holding the
	 *                   {@code .list} files (one CIDR per line)
	 * @param bundledDefaults File names shipped in the jar under
	 *                        {@code /<folderName>/} to copy in when missing
	 * @throws CIDRException When the lists cannot be loaded
	 */
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

	/**
	 * Copies bundled default list files from the jar into the folder, but
	 * only when the target file does not exist yet, so user edits survive
	 * updates.
	 */
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
					// Blank lines and '#' comments are ignored so the
					// shipped default files can document themselves.
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
