package com.sme.cyberrisk.service.scanner;

import com.sme.cyberrisk.model.Finding;
import com.sme.cyberrisk.model.FindingCategory;
import com.sme.cyberrisk.model.Severity;
import org.springframework.stereotype.Component;

import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.*;

@Component
public class DnsEmailAuditor {

    public record EmailReport(String spfRecord, String dmarcRecord, boolean spoofable, List<Finding> findings) {}

    public EmailReport auditDomain(String domain) {
        List<Finding> findings = new ArrayList<>();
        String spf = null;
        String dmarc = null;
        boolean spoofable = true;

        // Skip pure IP addresses
        if (domain.matches("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$") || domain.contains("localhost")) {
            return new EmailReport("N/A (IP Address)", "N/A (IP Address)", false, findings);
        }

        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            env.put("java.naming.provider.url", "dns://8.8.8.8");
            env.put("com.sun.jndi.dns.timeout.initial", "2000");
            env.put("com.sun.jndi.dns.timeout.retries", "1");

            DirContext ictx = new InitialDirContext(env);

            // 1. Check SPF record
            try {
                Attributes attrs = ictx.getAttributes(domain, new String[]{"TXT"});
                Attribute txt = attrs.get("TXT");
                if (txt != null) {
                    NamingEnumeration<?> e = txt.getAll();
                    while (e.hasMore()) {
                        String val = e.next().toString().replaceAll("\"", "");
                        if (val.startsWith("v=spf1")) {
                            spf = val;
                            break;
                        }
                    }
                }
            } catch (Exception ignored) {}

            // 2. Check DMARC record
            try {
                Attributes dmarcAttrs = ictx.getAttributes("_dmarc." + domain, new String[]{"TXT"});
                Attribute txt = dmarcAttrs.get("TXT");
                if (txt != null) {
                    NamingEnumeration<?> e = txt.getAll();
                    while (e.hasMore()) {
                        String val = e.next().toString().replaceAll("\"", "");
                        if (val.startsWith("v=DMARC1")) {
                            dmarc = val;
                            break;
                        }
                    }
                }
            } catch (Exception ignored) {}

            // Evaluate SPF
            if (spf == null) {
                findings.add(new Finding(
                    FindingCategory.EMAIL_SECURITY,
                    Severity.HIGH,
                    "Missing SPF (Sender Policy Framework) Record",
                    "The domain " + domain + " has no SPF record published in DNS. Any malicious party can send emails masquerading as your company to commit wire fraud or impersonate management.",
                    "Add a DNS TXT record to " + domain + ": 'v=spf1 include:_spf.google.com ~all' (customize with your actual mail provider).",
                    "15 mins"
                ));
            } else if (spf.contains("+all")) {
                findings.add(new Finding(
                    FindingCategory.EMAIL_SECURITY,
                    Severity.CRITICAL,
                    "Insecure SPF Record (+all Allows Any Mail Server)",
                    "Your SPF record uses '+all', which explicitly authorizes every IP on the entire internet to send legitimate emails from @" + domain + "!",
                    "Change '+all' to '~all' (softfail) or '-all' (hardfail) immediately.",
                    "5 mins"
                ));
            }

            // Evaluate DMARC
            if (dmarc == null) {
                findings.add(new Finding(
                    FindingCategory.EMAIL_SECURITY,
                    Severity.CRITICAL,
                    "Missing DMARC Record (High Phishing / BEC Risk)",
                    "DMARC is the industry standard defense against Business Email Compromise (BEC). Without DMARC, major email providers (Google, Microsoft 365, Yahoo) will not reject forged emails using your brand name.",
                    "Publish a DNS TXT record at _dmarc." + domain + " with content: 'v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@" + domain + ";'",
                    "15 mins"
                ));
                spoofable = true;
            } else {
                if (dmarc.contains("p=none")) {
                    findings.add(new Finding(
                        FindingCategory.EMAIL_SECURITY,
                        Severity.MEDIUM,
                        "DMARC Policy Set to 'p=none' (Monitoring Only)",
                        "Your DMARC record is in reporting mode only. Forged emails impersonating your domain will still land in customer or vendor inboxes.",
                        "Progressively upgrade policy from 'p=none' to 'p=quarantine' and ultimately 'p=reject'.",
                        "20 mins"
                    ));
                    spoofable = true;
                } else if (dmarc.contains("p=reject") || dmarc.contains("p=quarantine")) {
                    findings.add(new Finding(
                        FindingCategory.EMAIL_SECURITY,
                        Severity.INFO,
                        "DMARC Strict Enforcement Active",
                        "DMARC is properly enforcing quarantine/rejection of spoofed emails. Excellent phishing protection for this domain.",
                        "Regularly monitor DMARC XML reports to confirm legitimate vendor emails are aligned.",
                        "5 mins"
                    ));
                    spoofable = false;
                }
            }

        } catch (Exception e) {
            findings.add(new Finding(
                FindingCategory.EMAIL_SECURITY,
                Severity.INFO,
                "DNS Record Check Notice",
                "DNS lookup for " + domain + " timed out or not resolved: " + e.getMessage(),
                "Ensure domain name is active and DNS nameservers are reachable.",
                "10 mins"
            ));
        }

        return new EmailReport(
            spf != null ? spf : "Not Configured",
            dmarc != null ? dmarc : "Not Configured",
            spoofable,
            findings
        );
    }
}
