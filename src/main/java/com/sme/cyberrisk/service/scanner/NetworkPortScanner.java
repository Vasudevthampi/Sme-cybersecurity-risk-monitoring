package com.sme.cyberrisk.service.scanner;

import com.sme.cyberrisk.model.Finding;
import com.sme.cyberrisk.model.FindingCategory;
import com.sme.cyberrisk.model.Severity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.*;
import java.util.concurrent.*;

@Component
public class NetworkPortScanner {

    @Value("${sme.scanner.socket-timeout-ms:1500}")
    private int timeoutMs;

    public record PortSpec(int port, String service, Severity riskWhenOpen, String riskDesc, String remediation, String timeEstimate) {}

    private static final List<PortSpec> MONITORED_PORTS = List.of(
        new PortSpec(21, "FTP", Severity.HIGH,
            "Unencrypted File Transfer Protocol (FTP) detected. Credentials and files transmitted in plaintext.",
            "Disable standard FTP and migrate to SFTP (SSH File Transfer Protocol) or FTPS with TLS encryption.", "15 mins"),
        new PortSpec(22, "SSH", Severity.LOW,
            "SSH remote management port is open. If password authentication is allowed, it is susceptible to brute-force.",
            "Enforce public-key authentication, change default port, and restrict access using a VPN or IP whitelist.", "20 mins"),
        new PortSpec(23, "Telnet", Severity.CRITICAL,
            "Telnet remote shell is open. Telnet transmits passwords and commands entirely unencrypted over the wire.",
            "Immediately disable Telnet service and switch to SSH.", "10 mins"),
        new PortSpec(25, "SMTP", Severity.MEDIUM,
            "Mail transfer port (SMTP) is exposed. If misconfigured, this server may act as an open spam relay.",
            "Ensure open relay is disabled and enforce SMTP authentication (STARTTLS).", "25 mins"),
        new PortSpec(80, "HTTP", Severity.LOW,
            "Unencrypted HTTP port is open.",
            "Configure automatic 301 redirection from HTTP to HTTPS (port 443).", "10 mins"),
        new PortSpec(110, "POP3", Severity.HIGH,
            "Unencrypted POP3 email retrieval port is exposed.",
            "Disable unencrypted POP3; use POP3S (port 995) or IMAPS (port 993) with SSL/TLS.", "15 mins"),
        new PortSpec(143, "IMAP", Severity.HIGH,
            "Unencrypted IMAP email retrieval port is exposed.",
            "Disable unencrypted IMAP; use IMAPS (port 993) with TLS encryption.", "15 mins"),
        new PortSpec(443, "HTTPS", Severity.INFO,
            "Encrypted HTTPS web service detected.",
            "Maintain valid SSL/TLS certificates and enforce modern cipher suites.", "5 mins"),
        new PortSpec(445, "SMB / Active Directory", Severity.CRITICAL,
            "Server Message Block (SMB) exposed to the network. This is the primary lateral movement vector for ransomware (e.g. WannaCry, NotPetya).",
            "CRITICAL: Never expose SMB (port 445) publicly. Block port 445 at firewall immediately. Use VPN for file sharing.", "5 mins"),
        new PortSpec(1433, "Microsoft SQL Server", Severity.CRITICAL,
            "MSSQL database listener is publicly exposed to network connections.",
            "Block port 1433 from public internet. Bind SQL Server to localhost (127.0.0.1) or internal subnet only.", "10 mins"),
        new PortSpec(3306, "MySQL Database", Severity.CRITICAL,
            "MySQL database port is exposed to the network.",
            "Never expose MySQL publicly. Configure 'bind-address = 127.0.0.1' and use SSH tunnels or VPN for remote access.", "10 mins"),
        new PortSpec(3389, "RDP (Remote Desktop)", Severity.CRITICAL,
            "Remote Desktop Protocol (RDP) is directly exposed. RDP brute-force is the #1 vector for ransomware attacks against small businesses.",
            "URGENT: Immediately close port 3389 at firewall. Require an encrypted VPN or Zero-Trust gateway before accessing RDP.", "10 mins"),
        new PortSpec(5432, "PostgreSQL Database", Severity.CRITICAL,
            "PostgreSQL database port is exposed to the network.",
            "Block port 5432 at perimeter firewall. Ensure pg_hba.conf only permits local/trusted subnets.", "10 mins"),
        new PortSpec(8080, "Alternative Web / Proxy", Severity.LOW,
            "Alternative HTTP port 8080 is open (commonly Tomcat, Jenkins, dev web servers).",
            "Ensure development services or administrative consoles on port 8080 are authenticated and protected.", "15 mins"),
        new PortSpec(27017, "MongoDB NoSQL", Severity.CRITICAL,
            "MongoDB port is open. Exposed MongoDB instances are routinely wiped and held for ransom by automated bots.",
            "Bind MongoDB to localhost, enable authentication, and block port 27017 at the firewall.", "10 mins")
    );

    public record ScanReport(int scannedCount, List<Integer> openPorts, List<Finding> findings) {}

    public ScanReport scanHost(String host) {
        List<Integer> openPorts = Collections.synchronizedList(new ArrayList<>());
        List<Finding> findings = Collections.synchronizedList(new ArrayList<>());

        ExecutorService executor = Executors.newFixedThreadPool(8);
        List<Future<?>> futures = new ArrayList<>();

        for (PortSpec spec : MONITORED_PORTS) {
            futures.add(executor.submit(() -> {
                if (isPortOpen(host, spec.port, timeoutMs)) {
                    openPorts.add(spec.port);
                    if (spec.riskWhenOpen != Severity.INFO) {
                        Finding finding = new Finding(
                            FindingCategory.NETWORK_PORTS,
                            spec.riskWhenOpen,
                            "Exposed Port " + spec.port + " (" + spec.service + ")",
                            spec.riskDesc,
                            spec.remediation,
                            spec.timeEstimate
                        );
                        findings.add(finding);
                    }
                }
            }));
        }

        for (Future<?> f : futures) {
            try {
                f.get(timeoutMs + 1000L, TimeUnit.MILLISECONDS);
            } catch (Exception ignored) {}
        }
        executor.shutdownNow();

        Collections.sort(openPorts);
        return new ScanReport(MONITORED_PORTS.size(), openPorts, findings);
    }

    private boolean isPortOpen(String host, int port, int timeout) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeout);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
