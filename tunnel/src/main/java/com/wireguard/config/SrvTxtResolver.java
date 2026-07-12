/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.config;

import android.util.Log;

import com.wireguard.util.NonNullForAll;

import org.xbill.DNS.ARecord;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.SRVRecord;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;

import androidx.annotation.Nullable;

/**
 * 解析 Endpoint 中的 SRV / TXT 记录，以及普通 A/AAAA。
 * <p>
 * 约定：
 * <ul>
 *   <li>SRV：主机名含 {@code ._tcp.} 或 {@code ._udp.}（大小写不敏感），端口写 0</li>
 *   <li>TXT：主机名含 {@code .txt.}（大小写不敏感），端口写 0，TXT 值为 {@code ip:port} 或 {@code [ipv6]:port}</li>
 *   <li>TXT 支持泛解析：主机名中第一个 {@code *} 替换为当前 Unix 秒级时间戳</li>
 *   <li>标记命中但端口非 0 时，按普通域名 A/AAAA 解析</li>
 * </ul>
 * <p>
 * 安卓上 dnsjava 读不到系统 DNS，SRV/TXT/A/AAAA 统一走显式公共 DNS；
 * A/AAAA 公共 DNS 失败后再回退 {@link InetAddress#getAllByName}。
 */
@NonNullForAll
public final class SrvTxtResolver {
    private static final String TAG = "SrvTxtResolver";
    /** 单次查询超时；多服务器串行时总耗时 ≈ 超时 × 服务器数 × 查询类型数 */
    private static final Duration DNS_TIMEOUT = Duration.ofSeconds(2);
    private static final String[] DNS_SERVERS = {"223.5.5.5", "8.8.8.8", "1.1.1.1"};

    private SrvTxtResolver() {
    }

    public static final class Result {
        private final String host;
        private final int port;

        public Result(final String host, final int port) {
            this.host = host;
            this.port = port;
        }

        public String getHost() {
            return host;
        }

        public int getPort() {
            return port;
        }

        public String toEndpointString() {
            final boolean isBareIpv6 = host.indexOf(':') >= 0;
            return (isBareIpv6 ? '[' + host + ']' : host) + ':' + port;
        }

        public boolean isValid() {
            return port > 0 && port <= 65535
                    && host != null && !host.isEmpty()
                    && !"0.0.0.0".equals(host)
                    && !"::".equals(host)
                    && !"0:0:0:0:0:0:0:0".equals(host);
        }
    }

    public static boolean isSrvHost(final String host) {
        if (host == null || host.isEmpty())
            return false;
        final String h = host.toLowerCase(Locale.ROOT);
        return h.contains("._tcp.") || h.contains("._udp.");
    }

    public static boolean isTxtHost(final String host) {
        if (host == null || host.isEmpty())
            return false;
        return host.toLowerCase(Locale.ROOT).contains(".txt.");
    }

    public static boolean isSrvOrTxtHost(final String host) {
        return isSrvHost(host) || isTxtHost(host);
    }

    /**
     * @return 成功返回有效 ip:port；失败 empty（绝不返回 0.0.0.0 或端口 0）
     */
    public static Optional<Result> resolve(final String host, final int port) {
        if (host == null || host.isEmpty())
            return Optional.empty();
        // 去掉首尾空白与末尾点，DNS 查询更稳
        String normalized = host.trim();
        while (normalized.endsWith(".") && normalized.length() > 1)
            normalized = normalized.substring(0, normalized.length() - 1);
        if (normalized.isEmpty())
            return Optional.empty();

        try {
            if (port == 0 && isSrvHost(normalized))
                return filterValid(resolveSrv(normalized));
            if (port == 0 && isTxtHost(normalized))
                return filterValid(resolveTxt(normalized));
            if (port <= 0 || port > 65535) {
                Log.w(TAG, "端口非法，拒绝解析: " + normalized + ":" + port);
                return Optional.empty();
            }
            return filterValid(resolveAddress(normalized, port));
        } catch (final Exception e) {
            Log.w(TAG, "解析失败 host=" + normalized + " port=" + port, e);
            return Optional.empty();
        }
    }

    private static Optional<Result> filterValid(final Optional<Result> result) {
        if (result.isEmpty())
            return result;
        if (!result.get().isValid()) {
            Log.w(TAG, "过滤无效结果: " + result.get().getHost() + ":" + result.get().getPort());
            return Optional.empty();
        }
        return result;
    }

    private static Optional<Result> resolveSrv(final String host) {
        final Record[] records = lookupRecords(host, Type.SRV);
        if (records == null || records.length == 0) {
            Log.w(TAG, "无 SRV 记录: " + host);
            return Optional.empty();
        }

        final List<SRVRecord> srvRecords = new ArrayList<>();
        for (final Record record : records) {
            if (record instanceof SRVRecord)
                srvRecords.add((SRVRecord) record);
        }
        if (srvRecords.isEmpty()) {
            Log.w(TAG, "SRV 响应中无有效记录: " + host);
            return Optional.empty();
        }

        final List<Integer> priorities = new ArrayList<>();
        for (final SRVRecord r : srvRecords) {
            final int p = r.getPriority();
            if (!priorities.contains(p))
                priorities.add(p);
        }
        priorities.sort(Integer::compareTo);

        for (final int priority : priorities) {
            final List<SRVRecord> remaining = new ArrayList<>();
            for (final SRVRecord r : srvRecords) {
                if (r.getPriority() == priority)
                    remaining.add(r);
            }
            while (!remaining.isEmpty()) {
                final int idx = pickSrvIndex(remaining);
                final SRVRecord chosen = remaining.remove(idx);

                String target = chosen.getTarget().toString();
                while (target.endsWith(".") && target.length() > 1)
                    target = target.substring(0, target.length() - 1);
                target = target.trim();

                final int srvPort = chosen.getPort();
                if (srvPort <= 0 || srvPort > 65535) {
                    Log.w(TAG, "SRV 端口非法: " + srvPort + " target=" + target);
                    continue;
                }
                if (target.isEmpty() || ".".equals(target)) {
                    Log.w(TAG, "SRV target 为空");
                    continue;
                }

                Log.i(TAG, "SRV " + host + " 尝试 " + target + ":" + srvPort
                        + " (priority=" + chosen.getPriority() + ", weight=" + chosen.getWeight() + ")");
                final Optional<Result> addr = resolveAddress(target, srvPort);
                if (addr.isPresent() && addr.get().isValid())
                    return addr;
                Log.w(TAG, "SRV target 地址解析失败: " + target);
            }
        }
        return Optional.empty();
    }

    private static int pickSrvIndex(final List<SRVRecord> records) {
        final int size = records.size();
        if (size <= 0)
            throw new IllegalArgumentException("empty SRV list");
        if (size == 1)
            return 0;

        int totalWeight = 0;
        for (final SRVRecord r : records)
            totalWeight += Math.max(r.getWeight(), 0);

        if (totalWeight <= 0)
            return ThreadLocalRandom.current().nextInt(size);

        int cursor = ThreadLocalRandom.current().nextInt(totalWeight);
        for (int i = 0; i < size; i++) {
            cursor -= Math.max(records.get(i).getWeight(), 0);
            if (cursor < 0)
                return i;
        }
        return size - 1;
    }

    private static Optional<Result> resolveTxt(final String host) {
        final String txtHost = expandTxtWildcard(host);
        Log.i(TAG, "解析 TXT: " + txtHost + (txtHost.equals(host) ? "" : " (原始=" + host + ")"));

        final Record[] records = lookupRecords(txtHost, Type.TXT);
        if (records == null || records.length == 0) {
            Log.w(TAG, "无 TXT 记录: " + txtHost);
            return Optional.empty();
        }

        for (final Record record : records) {
            if (!(record instanceof TXTRecord))
                continue;
            final TXTRecord txtRecord = (TXTRecord) record;
            @SuppressWarnings("unchecked")
            final List<String> strings = txtRecord.getStrings();
            if (strings == null || strings.isEmpty())
                continue;

            final StringBuilder sb = new StringBuilder();
            for (final String s : strings) {
                if (s != null)
                    sb.append(s);
            }
            final String txtValue = sb.toString().trim();
            if (txtValue.isEmpty())
                continue;
            Log.i(TAG, "TXT 值: " + txtValue);

            final Optional<Result> parsed = parseIpPort(txtValue);
            if (parsed.isPresent())
                return parsed;
            Log.w(TAG, "TXT 值无法解析为 ip:port: " + txtValue);
        }
        return Optional.empty();
    }

    static String expandTxtWildcard(final String host) {
        final int star = host.indexOf('*');
        if (star < 0)
            return host;
        return host.substring(0, star)
                + Instant.now().getEpochSecond()
                + host.substring(star + 1);
    }

    static Optional<Result> parseIpPort(final String value) {
        if (value == null || value.isEmpty())
            return Optional.empty();

        final String trimmed = value.trim();
        if (trimmed.isEmpty())
            return Optional.empty();

        final String ip;
        final String portStr;
        if (trimmed.startsWith("[")) {
            final int close = trimmed.indexOf(']');
            if (close <= 1 || close + 1 >= trimmed.length() || trimmed.charAt(close + 1) != ':')
                return Optional.empty();
            if (close + 2 >= trimmed.length())
                return Optional.empty();
            ip = trimmed.substring(1, close).trim();
            portStr = trimmed.substring(close + 2).trim();
        } else {
            final int colon = trimmed.lastIndexOf(':');
            if (colon <= 0 || colon == trimmed.length() - 1)
                return Optional.empty();
            if (trimmed.indexOf(':') != colon)
                return Optional.empty();
            ip = trimmed.substring(0, colon).trim();
            portStr = trimmed.substring(colon + 1).trim();
        }

        if (ip.isEmpty() || portStr.isEmpty())
            return Optional.empty();
        // 端口只允许纯数字，避免 51820abc 被部分接受
        for (int i = 0; i < portStr.length(); i++) {
            if (!Character.isDigit(portStr.charAt(i)))
                return Optional.empty();
        }

        try {
            InetAddresses.parse(ip);
            final int p = Integer.parseInt(portStr);
            final Result r = new Result(ip, p);
            if (!r.isValid())
                return Optional.empty();
            return Optional.of(r);
        } catch (final Exception e) {
            Log.w(TAG, "ip:port 校验失败: " + value, e);
            return Optional.empty();
        }
    }

    private static Optional<Result> resolveAddress(final String host, final int port) {
        if (port <= 0 || port > 65535) {
            Log.w(TAG, "端口非法: " + port);
            return Optional.empty();
        }
        if (host == null || host.isEmpty())
            return Optional.empty();

        try {
            InetAddresses.parse(host);
            final Result r = new Result(host, port);
            if (!r.isValid()) {
                Log.w(TAG, "无效数值地址: " + host);
                return Optional.empty();
            }
            return Optional.of(r);
        } catch (final ParseException ignored) {
            // 域名
        }

        final Optional<String> publicIp = lookupIpViaPublicDns(host);
        if (publicIp.isPresent())
            return Optional.of(new Result(publicIp.get(), port));

        try {
            final InetAddress[] candidates = InetAddress.getAllByName(host);
            if (candidates == null || candidates.length == 0)
                throw new UnknownHostException(host);

            InetAddress address = candidates[0];
            for (final InetAddress candidate : candidates) {
                if (candidate instanceof Inet4Address) {
                    address = candidate;
                    break;
                }
            }
            @Nullable String ip = address.getHostAddress();
            if (ip == null || ip.isEmpty()) {
                Log.w(TAG, "系统解析到空地址: " + host);
                return Optional.empty();
            }
            final int zone = ip.indexOf('%');
            if (zone >= 0)
                ip = ip.substring(0, zone);
            final Result r = new Result(ip, port);
            if (!r.isValid()) {
                Log.w(TAG, "系统解析到无效地址: " + host + " -> " + ip);
                return Optional.empty();
            }
            Log.i(TAG, "系统 DNS 解析 " + host + " -> " + ip);
            return Optional.of(r);
        } catch (final UnknownHostException e) {
            Log.w(TAG, "地址解析失败: " + host, e);
            return Optional.empty();
        }
    }

    private static Optional<String> lookupIpViaPublicDns(final String host) {
        final Record[] aRecords = lookupRecords(host, Type.A);
        if (aRecords != null) {
            for (final Record record : aRecords) {
                if (!(record instanceof ARecord))
                    continue;
                final InetAddress addr = ((ARecord) record).getAddress();
                if (addr == null)
                    continue;
                @Nullable final String ip = addr.getHostAddress();
                if (ip != null && !ip.isEmpty() && !"0.0.0.0".equals(ip)) {
                    Log.i(TAG, "公共 DNS A " + host + " -> " + ip);
                    return Optional.of(ip);
                }
            }
        }
        final Record[] aaaaRecords = lookupRecords(host, Type.AAAA);
        if (aaaaRecords != null) {
            for (final Record record : aaaaRecords) {
                if (!(record instanceof AAAARecord))
                    continue;
                final InetAddress addr = ((AAAARecord) record).getAddress();
                if (addr == null)
                    continue;
                @Nullable String ip = addr.getHostAddress();
                if (ip == null || ip.isEmpty())
                    continue;
                final int zone = ip.indexOf('%');
                if (zone >= 0)
                    ip = ip.substring(0, zone);
                if (!"::".equals(ip) && !"0:0:0:0:0:0:0:0".equals(ip)) {
                    Log.i(TAG, "公共 DNS AAAA " + host + " -> " + ip);
                    return Optional.of(ip);
                }
            }
        }
        return Optional.empty();
    }

    @Nullable
    private static Record[] lookupRecords(final String name, final int type) {
        Record[] last = null;
        for (final String server : DNS_SERVERS) {
            last = runLookup(name, type, server);
            if (last != null && last.length > 0)
                return last;
        }
        return last;
    }

    @Nullable
    private static Record[] runLookup(final String name, final int type, final String dnsServer) {
        try {
            final SimpleResolver resolver = new SimpleResolver(dnsServer);
            resolver.setPort(53);
            resolver.setTimeout(DNS_TIMEOUT);
            resolver.setTCP(false);
            resolver.setIgnoreTruncation(false);

            // 查询名统一小写 + 绝对域名
            String queryName = name.trim().toLowerCase(Locale.ROOT);
            while (queryName.endsWith(".") && queryName.length() > 1)
                queryName = queryName.substring(0, queryName.length() - 1);
            if (queryName.isEmpty())
                return null;
            final String absolute = queryName + ".";

            final Lookup lookup = new Lookup(Name.fromString(absolute), type);
            lookup.setResolver(resolver);
            lookup.setSearchPath(new String[0]);
            lookup.setCache(null);

            final Record[] records = lookup.run();
            if (lookup.getResult() != Lookup.SUCCESSFUL) {
                Log.w(TAG, "DNS 查询失败 name=" + name + " type=" + type
                        + " server=" + dnsServer + " err=" + lookup.getErrorString());
                return null;
            }
            return records;
        } catch (final Exception e) {
            Log.w(TAG, "DNS 查询异常 name=" + name + " server=" + dnsServer, e);
            return null;
        }
    }
}
