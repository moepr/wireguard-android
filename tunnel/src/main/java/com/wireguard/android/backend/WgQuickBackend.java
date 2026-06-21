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
import com.wireguard.crypto.Key;
import com.wireguard.util.NonNullForAll;

import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.SRVRecord;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

import java.io.File;
import java.io.FileOutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
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
     * 解析并替换地址端口
     * @param endpointLine
     * @return
     * @throws Exception
     */
    private static String replaceSrvAndIp4p(String endpointLine) throws Exception {
        //添加srv和txt转发支持
        Log.i(TAG, "============endpointLine: " + endpointLine);
        String endpoint = endpointLine.replace("Endpoint", "").trim();
        endpoint = endpoint.replace("endpoint", "").trim();
        endpoint = endpoint.replace("=", "").trim();
        final String[] endpointSplit = endpoint.split(":");
        final String host = endpointSplit[0];
        final int port = Integer.parseInt(endpointSplit[1]);
        Log.i(TAG, "============endpointLine host: " + host);
        Log.i(TAG, "============endpointLine port: " + port);
        if (port == 0) {
            String realHostIp = host;
            int realPort = 0;
            if((host.contains("._tcp.") || host.contains("._udp."))){
                //走解析srv逻辑
                Log.i(TAG, "============endpointLine 走解析srv逻辑: " + host);
                SimpleResolver resolver = new SimpleResolver("223.5.5.5");
                resolver.setPort(53);
                final Lookup lookup = new Lookup(host, Type.SRV);
                lookup.setResolver(resolver);
                final Record[] records = lookup.run();
                Log.i(TAG, "============endpointLine records: " + records);
                if (records != null) {
                    final Record record = records[0];
                    Log.i(TAG, "============endpointLine record: " + record);
                    if (record instanceof final SRVRecord srvRecord) {
                        Log.i(TAG, "============endpointLine srvRecord: " + srvRecord);
                        final String target = srvRecord.getTarget().toString();
                        Log.i(TAG, "============endpointLine target: " + target);
                        final InetAddress[] candidates = InetAddress.getAllByName(target);
                        InetAddress address = candidates[0];
                        Log.i(TAG, "============endpointLine address: " + address);
                        for (final InetAddress candidate : candidates) {
                            if (candidate instanceof Inet4Address) {
                                address = candidate;
                                break;
                            }
                        }
                        Log.i(TAG, "============endpointLine address2: " + address);
                        realHostIp = address.getHostAddress();
                        realPort = srvRecord.getPort();
                    }
                } else {
                    realHostIp = "0.0.0.0";
                }
            } else if(host.contains(".txt.")){
                //走解析txt逻辑，txt记录格式为 ip:端口
                //支持泛解析：*替换为当前Unix时间戳，如 *.xxx.txt.example.com -> 1718400000.xxx.txt.example.com
                String txtHost;
                if (host.contains("*")) {
                    txtHost = host.replace("*", String.valueOf(System.currentTimeMillis() / 1000));
                    Log.i(TAG, "============endpointLine 走解析txt泛解析 host:"+host+" -> "+txtHost);
                } else {
                    txtHost = host;
                }
                Log.i(TAG, "============endpointLine 走解析txt逻辑: " + txtHost);
                SimpleResolver resolver = new SimpleResolver("223.5.5.5");
                resolver.setPort(53);
                final Lookup lookup = new Lookup(txtHost, Type.TXT);
                lookup.setResolver(resolver);
                final Record[] records = lookup.run();
                Log.i(TAG, "============endpointLine txt records: " + records);
                if (records != null && records.length > 0) {
                    final Record record = records[0];
                    if (record instanceof final TXTRecord txtRecord) {
                        @SuppressWarnings("unchecked")
                        final List<String> txtStrings = txtRecord.getStrings();
                        Log.i(TAG, "============endpointLine txtStrings: " + txtStrings);
                        if (txtStrings != null && !txtStrings.isEmpty()) {
                            final String txtValue = txtStrings.get(0);
                            Log.i(TAG, "============endpointLine txtValue: " + txtValue);
                            //txt记录格式为 ip:端口，如 1.2.3.4:51820
                            final int colonIndex = txtValue.lastIndexOf(':');
                            if (colonIndex > 0) {
                                final String txtIp = txtValue.substring(0, colonIndex);
                                final String txtPort = txtValue.substring(colonIndex + 1);
                                // 简单验证ip格式
                                InetAddress.getByName(txtIp);
                                realHostIp = txtIp;
                                realPort = Integer.parseInt(txtPort);
                            }
                        }
                    }
                } else {
                    realHostIp = "0.0.0.0";
                }
            } else {
                // 普通DNS解析，默认优先选择v4地址
                final InetAddress[] candidates = InetAddress.getAllByName(host);
                InetAddress address = candidates[0];
                for (final InetAddress candidate : candidates) {
                    if (candidate instanceof Inet4Address) {
                        address = candidate;
                        break;
                    }
                }
                realHostIp = address.getHostAddress();
            }
            Log.i(TAG, "============endpointLine realHostIp: " + realHostIp);
            Log.i(TAG, "============endpointLine realPort: " + realPort);
            endpointLine = endpointLine.replace(host,realHostIp);
            endpointLine = endpointLine.replace(":"+port,":"+realPort);
            //endpointLine = "Endpoint = " + realHostIp + ":" + realPort;
            Log.i(TAG, "============endpointLine replaced: " + endpointLine);
        }
        return endpointLine;
    }

    private void setStateInternal(final Tunnel tunnel, @Nullable final Config config, final State state) throws Exception {
        Log.i(TAG, "Bringing tunnel " + tunnel.getName() + ' ' + state);

        Objects.requireNonNull(config, "Trying to set state up with a null config");
        Log.i(TAG, "============localTemporaryDir: " + localTemporaryDir);
        File tempFile = new File(localTemporaryDir, tunnel.getName() + ".conf");

        //final File tempFile = new File(localTemporaryDir, tunnel.getName() + ".conf");
        try (final FileOutputStream stream = new FileOutputStream(tempFile, false)) {
            stream.write(config.toWgQuickString().getBytes(StandardCharsets.UTF_8));
        }
        String command = String.format("wg-quick %s '%s'",
                state.toString().toLowerCase(Locale.ENGLISH), tempFile.getAbsolutePath());
        if (state == State.UP)
            command = "cat /sys/module/wireguard/version && " + command;
        Log.i(TAG, "============tempFile: " + tempFile);
        Log.i(TAG, "============tempFile exists: " + tempFile.exists());
        /*
         * 解析srv/txt，修改tempFile文件中地址和端口，解决内核模式无法使用srv/txt的问题
         */
        //1.读取文件内容：将文件内容读入内存。
        List<String> lines = Files.readAllLines(tempFile.toPath());
        for (int i = 0; i < lines.size(); i++) {
            String lineStr = lines.get(i);
            if(lineStr.startsWith("Endpoint")||lineStr.startsWith("endpoint")){
                //2.修改文件内容：对读入的内容进行所需的修改。
                lineStr = replaceSrvAndIp4p(lineStr);
            }
            lines.set(i, lineStr);
        }
        //3.写回文件内容：将修改后的内容写回文件
        Files.write(tempFile.toPath(), lines);
        final int result = rootShell.run(null, command);
        // noinspection ResultOfMethodCallIgnored
        tempFile.delete();
        if (result != 0)
            throw new BackendException(Reason.WG_QUICK_CONFIG_ERROR_CODE, result);

        if (state == State.UP) {
            runningConfigs.put(tunnel, config);
            tunnel.onStateChange(state);
            // 隧道开启成功后启动握手超时监视器
            startHandshakeMonitor(tunnel, config);
        } else {
            // 关闭隧道时停止握手超时监视器
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
