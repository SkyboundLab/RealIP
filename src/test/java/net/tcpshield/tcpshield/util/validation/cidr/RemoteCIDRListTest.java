package net.tcpshield.tcpshield.util.validation.cidr;

import com.sun.net.httpserver.HttpServer;
import net.tcpshield.tcpshield.TCPShieldPacketHandler;
import net.tcpshield.tcpshield.TCPShieldPlugin;
import net.tcpshield.tcpshield.provider.ConfigProvider;
import net.tcpshield.tcpshield.util.Debugger;
import net.tcpshield.tcpshield.util.exception.config.ConfigLoadException;
import net.tcpshield.tcpshield.util.exception.config.ConfigReloadException;
import net.tcpshield.tcpshield.util.exception.config.ConfigResetException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Guards the auto-fetch of TCPShield's IP ranges: the list starts from the
 * bundled baseline (or the persisted cache), a successful refresh replaces
 * it wholesale, and any failed or empty refresh keeps the previous list.
 * Fetching is tested against a real local HTTP server, not the internet.
 */
public class RemoteCIDRListTest {

	private static final Logger LOGGER = Logger.getLogger("test");

	private static boolean matchesAny(List<CIDRMatcher> matchers, String address) throws Exception {
		InetAddress inetAddress = InetAddress.getByName(address);
		for (CIDRMatcher matcher : matchers)
			if (matcher.match(inetAddress))
				return true;
		return false;
	}

	/** Minimal TCPShieldPlugin stub so CIDRValidator can be exercised. */
	private static class TestConfig extends ConfigProvider {
		TestConfig(File dataFolder) {
			this.dataFolder = dataFolder;
		}

		@Override
		protected void reset() throws ConfigResetException {
		}

		@Override
		protected void load() throws ConfigLoadException {
		}

		@Override
		public void reload() throws ConfigReloadException {
		}

		@Override
		protected void checkNodes(String... nodes) {
		}
	}

	private static class TestPlugin implements TCPShieldPlugin {
		private final ConfigProvider config;

		TestPlugin(File dataFolder) {
			this.config = new TestConfig(dataFolder);
		}

		@Override
		public ConfigProvider getConfigProvider() {
			return config;
		}

		@Override
		public Logger getLogger() {
			return LOGGER;
		}

		@Override
		public TCPShieldPacketHandler getPacketHandler() {
			return null;
		}

		@Override
		public Debugger getDebugger() {
			return Debugger.createDebugger(this);
		}
	}

	private static HttpServer serve(String v4Body, String v4cfBody) throws Exception {
		HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/v4", exchange -> {
			byte[] body = v4Body.getBytes(StandardCharsets.UTF_8);
			exchange.sendResponseHeaders(200, body.length);
			try (OutputStream out = exchange.getResponseBody()) {
				out.write(body);
			}
		});
		server.createContext("/v4-cf", exchange -> {
			byte[] body = v4cfBody.getBytes(StandardCharsets.UTF_8);
			exchange.sendResponseHeaders(200, body.length);
			try (OutputStream out = exchange.getResponseBody()) {
				out.write(body);
			}
		});
		server.setExecutor(null);
		server.start();
		return server;
	}

	private static String baseUrl(HttpServer server) {
		return "http://127.0.0.1:" + server.getAddress().getPort();
	}

	@Test
	public void startsFromBaselineWhenNothingFetched(@TempDir Path tempDir) throws Exception {
		RemoteCIDRList list = new RemoteCIDRList(LOGGER, tempDir.resolve("cache").toFile(),
				List.of("http://127.0.0.1:1/v4", "http://127.0.0.1:1/v4-cf"),
				List.of("203.0.113.0/24", "198.51.100.7/32"));

		assertFalse(list.refresh()); // unreachable: keeps the baseline
		assertTrue(matchesAny(list.currentMatchers(), "203.0.113.44"));
		assertTrue(matchesAny(list.currentMatchers(), "198.51.100.7"));
		assertFalse(matchesAny(list.currentMatchers(), "192.0.2.1"));
	}

	@Test
	public void successfulRefreshReplacesTheWholeList(@TempDir Path tempDir) throws Exception {
		HttpServer server = serve(
				"# comment\n\n198.178.119.0/24\nnot-a-cidr\n104.234.6.0/25\n",
				"89.222.122.36/31\n");
		try {
			RemoteCIDRList list = new RemoteCIDRList(LOGGER, tempDir.resolve("cache").toFile(),
					List.of(baseUrl(server) + "/v4", baseUrl(server) + "/v4-cf"),
					List.of("203.0.113.0/24"));

			assertTrue(list.refresh());

			// Fetched ranges apply, including the /31 and the /25 edge
			assertTrue(matchesAny(list.currentMatchers(), "198.178.119.200"));
			assertTrue(matchesAny(list.currentMatchers(), "104.234.6.127"));
			assertFalse(matchesAny(list.currentMatchers(), "104.234.6.128"));
			assertTrue(matchesAny(list.currentMatchers(), "89.222.122.37"));
			// The IPv6 range is kept even though no v6 source exists
			assertTrue(matchesAny(list.currentMatchers(), "2602:fa78::1"));
			// The old baseline is gone: wholesale replacement, not a union
			assertFalse(matchesAny(list.currentMatchers(), "203.0.113.44"));
		} finally {
			server.stop(0);
		}
	}

	@Test
	public void failedRefreshKeepsThePreviousList(@TempDir Path tempDir) throws Exception {
		HttpServer server = serve("198.178.119.0/24\n", "89.222.122.36/31\n");
		try {
			RemoteCIDRList list = new RemoteCIDRList(LOGGER, tempDir.resolve("cache").toFile(),
					List.of(baseUrl(server) + "/v4", baseUrl(server) + "/v4-cf"),
					List.of("203.0.113.0/24"));
			assertTrue(list.refresh());
			assertTrue(matchesAny(list.currentMatchers(), "198.178.119.200"));

			server.stop(0); // sources go away mid-test
			assertFalse(list.refresh());

			// Still the fetched list, not the baseline and not empty
			assertTrue(matchesAny(list.currentMatchers(), "198.178.119.200"));
			assertFalse(matchesAny(list.currentMatchers(), "203.0.113.44"));
		} finally {
			server.stop(0);
		}
	}

	@Test
	public void emptySourceKeepsThePreviousList(@TempDir Path tempDir) throws Exception {
		HttpServer server = serve("198.178.119.0/24\n", "# nothing here\n\n");
		try {
			RemoteCIDRList list = new RemoteCIDRList(LOGGER, tempDir.resolve("cache").toFile(),
					List.of(baseUrl(server) + "/v4", baseUrl(server) + "/v4-cf"),
					List.of("203.0.113.0/24"));
			assertFalse(list.refresh()); // second source is empty
			assertTrue(matchesAny(list.currentMatchers(), "203.0.113.44"));
			assertFalse(matchesAny(list.currentMatchers(), "198.178.119.200"));
		} finally {
			server.stop(0);
		}
	}

	@Test
	public void cacheSurvivesARestartWithoutNetwork(@TempDir Path tempDir) throws Exception {
		File cacheFile = tempDir.resolve("cache").toFile();
		HttpServer server = serve("198.178.119.0/24\n", "89.222.122.36/31\n");
		try {
			RemoteCIDRList first = new RemoteCIDRList(LOGGER, cacheFile,
					List.of(baseUrl(server) + "/v4", baseUrl(server) + "/v4-cf"),
					List.of("203.0.113.0/24"));
			assertTrue(first.refresh());
			assertTrue(cacheFile.exists());
		} finally {
			server.stop(0);
		}

		// New instance, sources unreachable: starts from the cache
		RemoteCIDRList second = new RemoteCIDRList(LOGGER, cacheFile,
				List.of("http://127.0.0.1:1/v4", "http://127.0.0.1:1/v4-cf"),
				List.of("203.0.113.0/24"));
		assertTrue(matchesAny(second.currentMatchers(), "198.178.119.200"));
		assertTrue(matchesAny(second.currentMatchers(), "89.222.122.37"));
		assertFalse(matchesAny(second.currentMatchers(), "203.0.113.44"));
	}

	@Test
	public void validatorDropsRemovedRangesEvenForSeenIps(@TempDir Path tempDir) throws Exception {
		File dataFolder = tempDir.resolve("plugin").toFile();
		assertTrue(dataFolder.mkdirs());
		CIDRValidator validator = new CIDRValidator(new TestPlugin(dataFolder), "ip-whitelist");

		validator.setRemoteMatchers(List.of(CIDRMatcher.create("192.168.2.0/24")));
		assertTrue(validator.validate(InetAddress.getByName("192.168.2.50")));

		// The range is withdrawn: the previously seen IP must stop matching
		validator.setRemoteMatchers(List.of());
		assertFalse(validator.validate(InetAddress.getByName("192.168.2.50")));
	}
}
