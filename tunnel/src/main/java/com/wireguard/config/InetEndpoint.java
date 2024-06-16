/*
 * Copyright © 2017-2023 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.config;

import com.wireguard.util.NonNullForAll;

import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.SRVRecord;
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
        if(endpoint.contains("._tcp.")||endpoint.contains("._udp.")){
            //srv格式使用URL解析
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
                    //TODO 添加srv和ip4p支持
                    String realHostIp = "0.0.0.0";
                    int realPort = port;
                    if(port == 0 && (host.contains("._tcp.") || host.contains("._udp."))){
                        //走解析srv逻辑
                        Lookup lookup = new Lookup(host, Type.SRV);
                        final Record[] records = lookup.run();
                        if (records != null) {
                            Record record = records[0];
                            if (record instanceof SRVRecord) {
                                SRVRecord srvRecord = (SRVRecord) record;
                                String target = srvRecord.getTarget().toString();
                                int port = srvRecord.getPort();
                                //int priority = srvRecord.getPriority();
                                //int weight = srvRecord.getWeight();
                                final InetAddress addr = InetAddress.getByName(target);
                                realPort = port;
                                realHostIp = addr.getHostAddress();
                            }
                        } else {
                            //System.out.println("No SRV records found for " + host);
                            realPort = 0;
                            realHostIp = "0.0.0.0";
                        }
                    } else {
                        // Prefer v4 endpoints over v6 to work around DNS64 and IPv6 NAT issues.
                        final InetAddress[] candidates = InetAddress.getAllByName(host);
                        InetAddress address = candidates[0];
                        for (final InetAddress candidate : candidates) {
                            if (candidate instanceof Inet4Address) {
                                address = candidate;
                                break;
                            }
                        }
                        String hostAddress = address.getHostAddress();
                        if(hostAddress.contains(":") && port==0){
                            //走解析ip4p逻辑
                            String[] split = hostAddress.split(":");
                            int port = Integer.parseInt(split[2], 16);
                            int ipab = Integer.parseInt(split[3], 16);
                            int ipcd = Integer.parseInt(split[4], 16);
                            int ipa = ipab >> 8;
                            int ipb = ipab & 0xff;
                            int ipc = ipcd >> 8;
                            int ipd = ipcd & 0xff;
                            realPort = port;
                            realHostIp = ipa+"."+ipb+"."+ipc+"."+ipd;
                        } else {
                            realHostIp = address.getHostAddress();
                        }
                    }
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
