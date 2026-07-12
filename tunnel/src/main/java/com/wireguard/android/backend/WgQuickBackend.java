/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.backend;

import android.content.Context;
import android.util.Log;
import android.util.Pair;

import com.wireguard.android.backend.BackendException.Reason;
import com.wireguard.android.backend.Tunnel.State;
import com.wireguard.android.util.RootShell;
import com.wireguard.android.util.ToolsInstaller;
import com.wireguard.config.Config;
import com.wireguard.config.InetEndpoint;
import com.wireguard.config.SrvTxtResolver;
import com.wireguard.crypto.Key;
import com.wireguard.util.NonNullForAll;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import androidx.annotation.Nullable;

/**
 * Implementation of {@link Backend} that uses the kernel module and {@code wg-quick} to provide
 * WireGuard tunnels.
 */

@NonNullForAll
public final class WgQuickBackend implements Backend {
    private static final String TAG = "WireGuard/WgQuickBackend";
    private final File localTemporaryDir;
    private final RootShell rootShell;
    private final Map<Tunnel, Config> runningConfigs = new HashMap<>();
    private final ToolsInstaller toolsInstaller;
    private boolean multipleTunnels;
    @Nullable private ScheduledExecutorService handshakeMonitor;

    public WgQuickBackend(final Context context, final RootShell rootShell, final ToolsInstaller toolsInstaller) {
        localTemporaryDir = new File(context.getCacheDir(), "tmp");
        this.rootShell = rootShell;
        this.toolsInstaller = toolsInstaller;
    }

    public static boolean hasKernelSupport() {
        return new File("/sys/module/wireguard").exists();
    }

    @Override
    public Set<String> getRunningTunnelNames() {
        final List<String> output = new ArrayList<>();
        // Don't throw an exception here or nothing will show up in the UI.
        try {
            toolsInstaller.ensureToolsAvailable();
            if (rootShell.run(output, "wg show interfaces") != 0 || output.isEmpty())
                return Collections.emptySet();
        } catch (final Exception e) {
            Log.w(TAG, "Unable to enumerate running tunnels", e);
            return Collections.emptySet();
        }
        // wg puts all interface names on the same line. Split them into separate elements.
        return Set.of(output.get(0).split(" "));
    }

    @Override
    public State getState(final Tunnel tunnel) {
        return getRunningTunnelNames().contains(tunnel.getName()) ? State.UP : State.DOWN;
    }

    @Override
    public Statistics getStatistics(final Tunnel tunnel) {
        final Statistics stats = new Statistics();
        final Collection<String> output = new ArrayList<>();
        try {
            if (rootShell.run(output, String.format("wg show '%s' dump", tunnel.getName())) != 0)
                return stats;
        } catch (final Exception ignored) {
            return stats;
        }
        for (final String line : output) {
            final String[] parts = line.split("\\t");
            if (parts.length != 8)
                continue;
            try {
                stats.add(Key.fromBase64(parts[0]), Long.parseLong(parts[5]), Long.parseLong(parts[6]), Long.parseLong(parts[4]) * 1000);
            } catch (final Exception ignored) {
            }
        }
        return stats;
    }

    @Override
    public String getVersion() throws Exception {
        final List<String> output = new ArrayList<>();
        if (rootShell.run(output, "cat /sys/module/wireguard/version") != 0 || output.isEmpty())
            throw new BackendException(Reason.UNKNOWN_KERNEL_MODULE_NAME);
        return output.get(0);
    }

    @Override
    public boolean isAlwaysOn() {
        return false;
    }

    @Override
    public boolean isLockdownEnabled() {
        return false;
    }

    public void setMultipleTunnels(final boolean on) {
        multipleTunnels = on;
    }

    @Override
    public State setState(final Tunnel tunnel, State state, @Nullable final Config config) throws Exception {
        final State originalState = getState(tunnel);
        final Config originalConfig = runningConfigs.get(tunnel);
        final Map<Tunnel, Config> runningConfigsSnapshot = new HashMap<>(runningConfigs);

        if (state == State.TOGGLE)
            state = originalState == State.UP ? State.DOWN : State.UP;
        if ((state == State.UP && originalState == State.UP && originalConfig != null && originalConfig == config) ||
                (state == State.DOWN && originalState == State.DOWN))
            return originalState;
        if (state == State.UP) {
            toolsInstaller.ensureToolsAvailable();
            if (!multipleTunnels && originalState == State.DOWN) {
                final List<Pair<Tunnel, Config>> rewind = new LinkedList<>();
                try {
                    for (final Map.Entry<Tunnel, Config> entry : runningConfigsSnapshot.entrySet()) {
                        setStateInternal(entry.getKey(), entry.getValue(), State.DOWN);
                        rewind.add(Pair.create(entry.getKey(), entry.getValue()));
                    }
                } catch (final Exception e) {
                    try {
                        for (final Pair<Tunnel, Config> entry : rewind) {
                            setStateInternal(entry.first, entry.second, State.UP);
                        }
                    } catch (final Exception ignored) {
                    }
                    throw e;
                }
            }
            if (originalState == State.UP)
                setStateInternal(tunnel, originalConfig == null ? config : originalConfig, State.DOWN);
            try {
                setStateInternal(tunnel, config, State.UP);
            } catch (final Exception e) {
                try {
                    if (originalState == State.UP && originalConfig != null) {
                        setStateInternal(tunnel, originalConfig, State.UP);
                    }
                    if (!multipleTunnels && originalState == State.DOWN) {
                        for (final Map.Entry<Tunnel, Config> entry : runningConfigsSnapshot.entrySet()) {
                            setStateInternal(entry.getKey(), entry.getValue(), State.UP);
                        }
                    }
                } catch (final Exception ignored) {
                }
                throw e;
            }
        } else if (state == State.DOWN) {
            setStateInternal(tunnel, originalConfig == null ? config : originalConfig, State.DOWN);
        }
        return state;
    }

    /**
     * 解析并替换 Endpoint 行中的 SRV/TXT 地址（端口为 0 时）。
     * SRV/TXT 解析失败抛异常（与用户态 GoBackend 行为一致）。
     */
    private static String replaceSrvAndIp4p(final String endpointLine) throws Exception {
        final String trimmedLine = endpointLine == null ? "" : endpointLine.trim();
        if (trimmedLine.isEmpty())
            return endpointLine;
        final int eq = trimmedLine.indexOf('=');
        if (eq <= 0)
            return endpointLine;
        final String key = trimmedLine.substring(0, eq).trim();
        if (!key.equalsIgnoreCase("Endpoint"))
            return endpointLine;

        final String endpoint = trimmedLine.substring(eq + 1).trim();
        if (endpoint.isEmpty())
            return endpointLine;

        // 复用统一解析，保证与用户态 host/port 拆分规则一致
        final InetEndpoint parsed;
        try {
            parsed = InetEndpoint.parse(endpoint);
        } catch (final Exception e) {
            Log.w(TAG, "Endpoint 格式无效: " + endpoint, e);
            return endpointLine;
        }

        final String host = parsed.getHost();
        final int port = parsed.getPort();

        // 仅 SRV/TXT（端口 0）需要预解析；其余交给 wg-quick
        if (port != 0 || !SrvTxtResolver.isSrvOrTxtHost(host))
            return endpointLine;

        Log.i(TAG, "解析 Endpoint: " + host + ":" + port);
        final Optional<SrvTxtResolver.Result> result = SrvTxtResolver.resolve(host, port);
        if (result.isEmpty() || !result.get().isValid()) {
            Log.w(TAG, "Endpoint 解析失败: " + endpoint);
            throw new Exception("SRV/TXT DNS 解析失败: " + host);
        }
        final SrvTxtResolver.Result r = result.get();
        final String replaced = "Endpoint = " + r.toEndpointString();
        Log.i(TAG, "Endpoint 替换: " + endpoint + " -> " + r.toEndpointString());
        return replaced;
    }

    private void setStateInternal(final Tunnel tunnel, @Nullable final Config config, final State state) throws Exception {
        Log.i(TAG, "Bringing tunnel " + tunnel.getName() + ' ' + state);

        Objects.requireNonNull(config, "Trying to set state up with a null config");
        if (!localTemporaryDir.isDirectory() && !localTemporaryDir.mkdirs())
            Log.w(TAG, "无法创建临时目录: " + localTemporaryDir);

        final File tempFile = new File(localTemporaryDir, tunnel.getName() + ".conf");
        try {
            try (final FileOutputStream stream = new FileOutputStream(tempFile, false)) {
                stream.write(config.toWgQuickString().getBytes(StandardCharsets.UTF_8));
            }
            String command = String.format("wg-quick %s '%s'",
                    state.toString().toLowerCase(Locale.ENGLISH), tempFile.getAbsolutePath());
            if (state == State.UP)
                command = "cat /sys/module/wireguard/version && " + command;
            Log.i(TAG, "tempFile: " + tempFile + " exists=" + tempFile.exists());

            /*
             * 仅在 UP 时解析 SRV/TXT 并改写 Endpoint。
             * DOWN 不查 DNS：避免 DNS 故障导致关隧道失败。
             */
            if (state == State.UP) {
                final List<String> lines = Files.readAllLines(tempFile.toPath());
                for (int i = 0; i < lines.size(); i++) {
                    String lineStr = lines.get(i);
                    final String trimmed = lineStr == null ? "" : lineStr.trim();
                    if (trimmed.regionMatches(true, 0, "Endpoint", 0, "Endpoint".length())) {
                        final int afterKey = "Endpoint".length();
                        if (trimmed.length() > afterKey) {
                            final char c = trimmed.charAt(afterKey);
                            if (c == '=' || Character.isWhitespace(c))
                                lineStr = replaceSrvAndIp4p(lineStr);
                        }
                    }
                    lines.set(i, lineStr);
                }
                Files.write(tempFile.toPath(), lines);
            }

            final int result = rootShell.run(null, command);
            if (result != 0)
                throw new BackendException(Reason.WG_QUICK_CONFIG_ERROR_CODE, result);
        } finally {
            // 无论成功/DNS失败/异常，都删除含私钥的临时 conf
            // noinspection ResultOfMethodCallIgnored
            tempFile.delete();
        }

        if (state == State.UP) {
            runningConfigs.put(tunnel, config);
            tunnel.onStateChange(state);
            startHandshakeMonitor(tunnel, config);
        } else {
            stopHandshakeMonitor();
            runningConfigs.remove(tunnel);
            tunnel.onStateChange(state);
        }
    }

    private void startHandshakeMonitor(final Tunnel tunnel, final Config config) {
        final Optional<Integer> timeoutOpt = config.getInterface().getHandshakeTimeout();
        if (timeoutOpt.isEmpty())
            return;
        final long timeoutSec = timeoutOpt.get();
        if (timeoutSec <= 0)
            return;
        stopHandshakeMonitor();
        handshakeMonitor = Executors.newSingleThreadScheduledExecutor(r -> {
            final Thread t = new Thread(r, "WgHandshakeMonitor");
            t.setDaemon(true);
            return t;
        });
        handshakeMonitor.scheduleWithFixedDelay(() -> {
            try {
                if (getState(tunnel) != State.UP)
                    return;
                final Statistics stats = getStatistics(tunnel);
                final long now = System.currentTimeMillis();
                boolean needReconnect = false;
                for (final Key key : stats.peers()) {
                    final Statistics.PeerStats peerStats = stats.peer(key);
                    if (peerStats == null) continue;
                    final long lastHandshake = peerStats.latestHandshakeEpochMillis();
                    if (lastHandshake > 0) {
                        final long elapsed = now - lastHandshake;
                        if (elapsed > timeoutSec * 1000L) {
                            Log.w(TAG, "Handshake timeout for peer " + key.toBase64()
                                    + " (elapsed=" + (elapsed / 1000) + "s, timeout=" + timeoutSec + "s). Reconnecting...");
                            needReconnect = true;
                        }
                    }
                }
                if (needReconnect) {
                    Log.i(TAG, "Performing handshake timeout reconnection for " + tunnel.getName());
                    try {
                        setState(tunnel, State.DOWN, null);
                        setState(tunnel, State.UP, config);
                    } catch (final Exception e) {
                        Log.w(TAG, "Handshake timeout reconnection failed", e);
                    }
                }
            } catch (final Exception e) {
                Log.w(TAG, "Handshake monitor error", e);
            }
        }, timeoutSec, Math.max(timeoutSec / 2, 10), TimeUnit.SECONDS);
    }

    private void stopHandshakeMonitor() {
        if (handshakeMonitor != null) {
            handshakeMonitor.shutdownNow();
            handshakeMonitor = null;
        }
    }
}
