/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.config;

import android.util.Log;

import com.wireguard.util.NonNullForAll;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.regex.Pattern;

import androidx.annotation.Nullable;


/**
 * An external endpoint (host and port) used to connect to a WireGuard {@link Peer}.
 * <p>
 * Instances of this class are externally immutable.
 */
@NonNullForAll
public final class InetEndpoint {
    private static final String TAG = "InetEndpoint";
    private static final Pattern BARE_IPV6 = Pattern.compile("^[^\\[\\]]*:[^\\[\\]]*");
    private static final Pattern FORBIDDEN_CHARACTERS = Pattern.compile("[/?#]");
    /** DNS 成功结果缓存时长 */
    private static final long RESOLUTION_CACHE_SECONDS = 60;

    private final String host;
    private final boolean isResolved;
    private final Object lock = new Object();
    private final int port;
    private Instant lastResolution = Instant.EPOCH;
    @Nullable private InetEndpoint resolved;

    private InetEndpoint(final String host, final boolean isResolved, final int port) {
        this.host = host;
        this.isResolved = isResolved;
        this.port = port;
    }

    public static InetEndpoint parse(final String endpoint) throws ParseException {
        if (endpoint == null || endpoint.isEmpty())
            throw new ParseException(InetEndpoint.class, endpoint == null ? "" : endpoint,
                    "Missing/invalid port number");
        if (FORBIDDEN_CHARACTERS.matcher(endpoint).find())
            throw new ParseException(InetEndpoint.class, endpoint, "Forbidden characters");

        final String trimmed = endpoint.trim();
        final int lastColon = trimmed.lastIndexOf(':');
        if (lastColon <= 0 || lastColon == trimmed.length() - 1)
            throw new ParseException(InetEndpoint.class, endpoint, "Missing/invalid port number");

        String hostPart = trimmed.substring(0, lastColon).trim();
        final String portPart = trimmed.substring(lastColon + 1).trim();
        if (hostPart.isEmpty() || portPart.isEmpty())
            throw new ParseException(InetEndpoint.class, endpoint, "Missing/invalid port number");

        // 端口只允许数字
        for (int i = 0; i < portPart.length(); i++) {
            if (!Character.isDigit(portPart.charAt(i)))
                throw new ParseException(InetEndpoint.class, endpoint, "Missing/invalid port number");
        }

        // [ipv6]:port
        if (hostPart.startsWith("[") && hostPart.endsWith("]") && hostPart.length() >= 2)
            hostPart = hostPart.substring(1, hostPart.length() - 1).trim();

        if (hostPart.isEmpty())
            throw new ParseException(InetEndpoint.class, endpoint, "Missing/invalid port number");

        // 裸 IPv6（无方括号且含多个冒号）无法可靠拆端口
        if (hostPart.indexOf(':') >= 0) {
            try {
                InetAddresses.parse(hostPart);
            } catch (final ParseException e) {
                throw new ParseException(InetEndpoint.class, endpoint, "Missing/invalid port number");
            }
        }

        // 主机名内不允许空白
        for (int i = 0; i < hostPart.length(); i++) {
            if (Character.isWhitespace(hostPart.charAt(i)))
                throw new ParseException(InetEndpoint.class, endpoint, "Forbidden characters");
        }

        final int parsedPort;
        try {
            parsedPort = Integer.parseInt(portPart);
        } catch (final NumberFormatException e) {
            throw new ParseException(InetEndpoint.class, endpoint, "Missing/invalid port number");
        }
        if (parsedPort < 0 || parsedPort > 65535)
            throw new ParseException(InetEndpoint.class, endpoint, "Missing/invalid port number");

        // 去掉域名末尾点，便于统一比较与解析
        while (hostPart.endsWith(".") && hostPart.length() > 1)
            hostPart = hostPart.substring(0, hostPart.length() - 1);

        try {
            InetAddresses.parse(hostPart);
            return new InetEndpoint(hostPart, true, parsedPort);
        } catch (final ParseException ignored) {
            return new InetEndpoint(hostPart, false, parsedPort);
        }
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof InetEndpoint))
            return false;
        final InetEndpoint other = (InetEndpoint) obj;
        return host.equals(other.host) && port == other.port;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    /**
     * 强制清除DNS解析缓存，下次调用getResolved()时会重新解析域名
     */
    public void resetResolution() {
        synchronized (lock) {
            lastResolution = Instant.EPOCH;
            resolved = null;
        }
    }

    /**
     * Generate an {@code InetEndpoint} instance with the same port and the host resolved using DNS
     * to a numeric address. If the host is already numeric, the existing instance may be returned.
     * Because this function may perform network I/O, it must not be called from the main thread.
     *
     * @return the resolved endpoint, or {@link Optional#empty()}
     */
    public Optional<InetEndpoint> getResolved() {
        if (isResolved) {
            // 数值地址也拒绝明显无效的 0.0.0.0/:: 与端口 0，避免用户态静默连黑洞
            if (port <= 0 || "0.0.0.0".equals(host) || "::".equals(host)
                    || "0:0:0:0:0:0:0:0".equals(host))
                return Optional.empty();
            return Optional.of(this);
        }
        synchronized (lock) {
            final boolean cacheExpired = lastResolution.equals(Instant.EPOCH)
                    || Duration.between(lastResolution, Instant.now()).getSeconds() >= RESOLUTION_CACHE_SECONDS;
            if (cacheExpired) {
                final Optional<SrvTxtResolver.Result> result = SrvTxtResolver.resolve(host, port);
                if (result.isPresent() && result.get().isValid()) {
                    final SrvTxtResolver.Result r = result.get();
                    Log.i(TAG, "解析成功 " + host + ":" + port + " -> " + r.getHost() + ":" + r.getPort());
                    resolved = new InetEndpoint(r.getHost(), true, r.getPort());
                    lastResolution = Instant.now();
                } else {
                    // 失败不更新 lastResolution，便于立即重试
                    // 保留旧 resolved，避免短暂 DNS 抖动导致断连
                    Log.w(TAG, "解析失败: " + host + ":" + port
                            + (resolved != null ? "（保留上次成功结果）" : ""));
                }
            }
            return Optional.ofNullable(resolved);
        }
    }

    @Override
    public int hashCode() {
        return host.hashCode() ^ port;
    }

    @Override
    public String toString() {
        final boolean isBareIpv6 = isResolved && BARE_IPV6.matcher(host).matches();
        return (isBareIpv6 ? '[' + host + ']' : host) + ':' + port;
    }
}
