/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.config;

import android.util.Log;

import com.wireguard.util.NonNullForAll;

import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.SRVRecord;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
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
    private static final Pattern BARE_IPV6 = Pattern.compile("^[^\\[\\]]*:[^\\[\\]]*");
    private static final Pattern FORBIDDEN_CHARACTERS = Pattern.compile("[/?#]");

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
        if (FORBIDDEN_CHARACTERS.matcher(endpoint).find())
            throw new ParseException(InetEndpoint.class, endpoint, "Forbidden characters");
        if(endpoint.contains("._tcp.")||endpoint.contains("._udp.")||endpoint.contains(".txt.")){
            //srv/txt格式使用URL解析（URL比URI容忍特殊字符如*）
            URL url;
            try {
                url = new URL("http://" + endpoint);
            } catch (final Exception e) {
                throw new ParseException(InetEndpoint.class, endpoint, e);
            }
            if (url.getPort() < 0 || url.getPort() > 65535)
                //无法解析对端错误
                throw new ParseException(InetEndpoint.class, endpoint, "Missing/invalid port number");
            try {
                InetAddresses.parse(url.getHost());
                // Parsing ths host as a numeric address worked, so we don't need to do DNS lookups.
                return new InetEndpoint(url.getHost(), true, url.getPort());
            } catch (final ParseException ignored) {
                // Failed to parse the host as a numeric address, so it must be a DNS hostname/FQDN.
                return new InetEndpoint(url.getHost(), false, url.getPort());
            }
        }
        final URI uri;
        try {
            uri = new URI("wg://" + endpoint);
        } catch (final URISyntaxException e) {
            throw new ParseException(InetEndpoint.class, endpoint, e);
        }
        if (uri.getPort() < 0 || uri.getPort() > 65535)
            //无法解析对端错误
            throw new ParseException(InetEndpoint.class, endpoint, "Missing/invalid port number");
        try {
            InetAddresses.parse(uri.getHost());
            // Parsing ths host as a numeric address worked, so we don't need to do DNS lookups.
            return new InetEndpoint(uri.getHost(), true, uri.getPort());
        } catch (final ParseException ignored) {
            // Failed to parse the host as a numeric address, so it must be a DNS hostname/FQDN.
            return new InetEndpoint(uri.getHost(), false, uri.getPort());
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
        if (isResolved)
            return Optional.of(this);
        synchronized (lock) {
            //TODO(zx2c4): Implement a real timeout mechanism using DNS TTL
            if (Duration.between(lastResolution, Instant.now()).toMinutes() > 1) {
                try {
                    Log.i("getResolved","==============host:"+host);
                    Log.i("getResolved","==============port:"+port);
                    //添加srv和txt转发支持
                    String realHostIp = "0.0.0.0";
                    int realPort = port;
                    if(port == 0 && (host.contains("._tcp.") || host.contains("._udp."))){
                        //走解析srv逻辑
                        Log.i("getResolved","==============走解析srv逻辑:"+host);
                        SimpleResolver resolver = new SimpleResolver("223.5.5.5");
                        resolver.setPort(53);
                        Lookup lookup = new Lookup(host, Type.SRV);
                        lookup.setResolver(resolver);
                        final Record[] records = lookup.run();
                        Log.i("getResolved","==============走解析srv逻辑 records:"+records);
                        if (records != null) {
                            Record record = records[0];
                            if (record instanceof SRVRecord) {
                                SRVRecord srvRecord = (SRVRecord) record;
                                String target = srvRecord.getTarget().toString();
                                int port = srvRecord.getPort();
                                final InetAddress[] candidates = InetAddress.getAllByName(target);
                                InetAddress address = candidates[0];
                                for (final InetAddress candidate : candidates) {
                                    if (candidate instanceof Inet4Address) {
                                        address = candidate;
                                        break;
                                    }
                                }
                                realPort = port;
                                realHostIp = address.getHostAddress();
                            }
                        } else {
                            //System.out.println("No SRV records found for " + host);
                            realPort = 0;
                            realHostIp = "0.0.0.0";
                        }
                    } else if(port == 0 && host.contains(".txt.")){
                        //走解析txt逻辑，txt记录格式为 ip:端口
                        //支持泛解析：*替换为当前Unix时间戳，如 *.xxx.txt.example.com -> 1718400000.xxx.txt.example.com
                        String txtHost;
                        if (host.contains("*")) {
                            txtHost = host.replace("*", String.valueOf(Instant.now().getEpochSecond()));
                            Log.i("getResolved","==============走解析txt泛解析 host:"+host+" -> "+txtHost);
                        } else {
                            txtHost = host;
                        }
                        Log.i("getResolved","==============走解析txt逻辑:"+txtHost);
                        SimpleResolver resolver = new SimpleResolver("223.5.5.5");
                        resolver.setPort(53);
                        Lookup lookup = new Lookup(txtHost, Type.TXT);
                        lookup.setResolver(resolver);
                        final Record[] records = lookup.run();
                        Log.i("getResolved","==============走解析txt逻辑 records:"+records);
                        if (records != null && records.length > 0) {
                            Record record = records[0];
                            if (record instanceof TXTRecord) {
                                TXTRecord txtRecord = (TXTRecord) record;
                                @SuppressWarnings("unchecked")
                                List<String> txtStrings = txtRecord.getStrings();
                                if (txtStrings != null && !txtStrings.isEmpty()) {
                                    String txtValue = txtStrings.get(0);
                                    Log.i("getResolved","==============走解析txt逻辑 txtValue:"+txtValue);
                                    //txt记录格式为 ip:端口，如 1.2.3.4:51820
                                    int colonIndex = txtValue.lastIndexOf(':');
                                    if (colonIndex > 0) {
                                        String txtIp = txtValue.substring(0, colonIndex);
                                        String txtPort = txtValue.substring(colonIndex + 1);
                                        InetAddresses.parse(txtIp); // 验证ip格式
                                        realHostIp = txtIp;
                                        realPort = Integer.parseInt(txtPort);
                                    }
                                }
                            }
                        } else {
                            realPort = 0;
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
                    Log.i("getResolved","==============解析结果 host:"+realHostIp+" port:"+realPort);
                    resolved = new InetEndpoint(realHostIp, true, realPort);
                    //resolved = new InetEndpoint(address.getHostAddress(), true, port);
                    lastResolution = Instant.now();
                } catch (final UnknownHostException e) {
                    resolved = null;
                } catch (TextParseException e) {
                    //throw new RuntimeException(e);
                    resolved = null;
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
