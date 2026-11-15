package net.tcpshield.tcpshield.util.validation.cidr;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.logging.Logger;

public class RemoteCIDRList {

	public static final List<String> SOURCE_URLS = List.of(
			"https://tcpshield.com/v4/",
			"https://tcpshield.com/v4-cf/"
	);

	/** TCPShield AS64199 IPv6 range; no v6 list endpoint exists. */
	public static final String IPV6_BASELINE = "2602:fa78::/40";

	public static final long REFRESH_INTERVAL_HOURS = 6;

	private static final int CONNECT_TIMEOUT_MS = 5000;
	private static final int READ_TIMEOUT_MS = 10000;
	private static final int MAX_LINES = 10000;
	private static final long MAX_BYTES = 1024 * 1024;

	private final Logger logger;
	private final File cacheFile;
	private final List<String> sourceUrls;
	private final List<String> baselineEntries;

	private volatile List<CIDRMatcher> currentMatchers = List.of();
	private volatile Consumer<List<CIDRMatcher>> onUpdate = matchers -> {
	};

	private ScheduledExecutorService scheduler;

	public RemoteCIDRList(Logger logger, File cacheFile) {
		this(logger, cacheFile, SOURCE_URLS, readBundledBaseline(logger));
	}

	public RemoteCIDRList(Logger logger, File cacheFile, List<String> sourceUrls, List<String> baselineEntries) {
		this.logger = logger;
		this.cacheFile = cacheFile;
		this.sourceUrls = List.copyOf(sourceUrls);
		this.baselineEntries = List.copyOf(baselineEntries);

		List<String> initial = readCacheFile();
		if (initial == null)
			initial = baselineEntries;
		setMatchers(toMatchers(initial));
	}

	public List<CIDRMatcher> currentMatchers() {
		return currentMatchers;
	}

	public void onUpdate(Consumer<List<CIDRMatcher>> onUpdate) {
		this.onUpdate = onUpdate;
	}

	public synchronized void start() {
		if (scheduler != null)
			return;
		scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
			Thread thread = new Thread(r, "TCPShield-IP-Refresh");
			thread.setDaemon(true);
			return thread;
		});
		scheduler.scheduleWithFixedDelay(this::refresh, 0, REFRESH_INTERVAL_HOURS, TimeUnit.HOURS);
	}

	public synchronized void stop() {
		if (scheduler != null) {
			scheduler.shutdownNow();
			scheduler = null;
		}
	}

	public boolean refresh() {
		Set<String> fetched = new LinkedHashSet<>();
		for (String url : sourceUrls) {
			List<String> entries;
			try {
				entries = fetch(url);
			} catch (Exception e) {
				logger.warning("TCPShield: failed to fetch IP ranges from " + url + " (" + e.getMessage() + "). Keeping the previous ranges.");
				return false;
			}
			if (entries.isEmpty()) {
				logger.warning("TCPShield: " + url + " returned no usable IP ranges. Keeping the previous ranges.");
				return false;
			}
			fetched.addAll(entries);
		}

		fetched.add(IPV6_BASELINE);
		List<CIDRMatcher> matchers = toMatchers(new ArrayList<>(fetched));
		writeCacheFile(new ArrayList<>(fetched));
		setMatchers(matchers);
		logger.info("TCPShield: refreshed IP ranges from tcpshield.com (" + fetched.size() + " entries).");
		return true;
	}

	private void setMatchers(List<CIDRMatcher> matchers) {
		currentMatchers = List.copyOf(matchers);
		onUpdate.accept(currentMatchers);
	}

	private List<String> fetch(String urlString) throws IOException {
		HttpURLConnection connection = (HttpURLConnection) new URL(urlString).openConnection();
		connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
		connection.setReadTimeout(READ_TIMEOUT_MS);
		connection.setInstanceFollowRedirects(true);
		connection.setRequestProperty("User-Agent", "TCPShield-RealIP/2.8.1");
		connection.setRequestProperty("Accept", "text/plain");

		int status = connection.getResponseCode();
		if (status != HttpURLConnection.HTTP_OK)
			throw new IOException("HTTP " + status);

		List<String> entries = new ArrayList<>();
		long bytesRead = 0;
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
			String line;
			while ((line = reader.readLine()) != null) {
				bytesRead += line.length() + 1;
				if (entries.size() >= MAX_LINES || bytesRead > MAX_BYTES)
					throw new IOException("response too large");
				String entry = line.trim();
				if (entry.isEmpty() || entry.startsWith("#"))
					continue;
				try {
					CIDRMatcher.create(entry); // validates the CIDR
					entries.add(entry);
				} catch (Exception e) {
					logger.warning("TCPShield: ignoring invalid IP range \"" + entry + "\" from " + urlString);
				}
			}
		} finally {
			connection.disconnect();
		}
		return entries;
	}

	private List<String> readCacheFile() {
		if (!cacheFile.exists())
			return null;
		try {
			List<String> entries = parseLines(Files.readAllLines(cacheFile.toPath(), StandardCharsets.UTF_8));
			if (entries.isEmpty()) {
				logger.warning("TCPShield: cached IP ranges file is empty, using the bundled ranges instead.");
				return null;
			}
			return entries;
		} catch (Exception e) {
			logger.warning("TCPShield: could not read cached IP ranges (" + e.getMessage() + "). Using the bundled ranges instead.");
			return null;
		}
	}

	private void writeCacheFile(List<String> entries) {
		try {
			File tempFile = new File(cacheFile.getParentFile(), cacheFile.getName() + ".tmp");
			Files.write(tempFile.toPath(), entries, StandardCharsets.UTF_8);
			Files.move(tempFile.toPath(), cacheFile.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
		} catch (Exception e) {
			logger.warning("TCPShield: could not save fetched IP ranges (" + e.getMessage() + "). The in-memory ranges are still in effect.");
		}
	}

	private List<CIDRMatcher> toMatchers(List<String> entries) {
		List<CIDRMatcher> matchers = new ArrayList<>();
		for (String entry : entries)
			try {
				matchers.add(CIDRMatcher.create(entry));
			} catch (Exception e) {
				logger.warning("TCPShield: ignoring invalid IP range \"" + entry + "\"");
			}
		return matchers;
	}

	private static List<String> parseLines(List<String> lines) {
		List<String> entries = new ArrayList<>();
		for (String line : lines) {
			String entry = line.trim();
			if (entry.isEmpty() || entry.startsWith("#"))
				continue;
			try {
				CIDRMatcher.create(entry);
				entries.add(entry);
			} catch (Exception ignored) {}
		}
		return entries;
	}

	private static List<String> readBundledBaseline(Logger logger) {
		try (InputStream in = RemoteCIDRList.class.getResourceAsStream("/proxy-whitelist/tcpshield-ips.list")) {
			if (in == null) {
				logger.warning("TCPShield: bundled IP ranges are missing from the jar. TCPShield connections will only work once the ranges have been fetched.");
				return List.of();
			}
			List<String> lines = new ArrayList<>();
			try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
				String line;
				while ((line = reader.readLine()) != null)
					lines.add(line);
			}
			List<String> entries = parseLines(lines);
			return entries;
		} catch (Exception e) {
			logger.warning("TCPShield: could not read bundled IP ranges (" + e.getMessage() + "). TCPShield connections will only work once the ranges have been fetched.");
			return List.of();
		}
	}
}
