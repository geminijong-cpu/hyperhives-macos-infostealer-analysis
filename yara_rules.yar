/*
   HyperHives macOS Rust Infostealer — YARA rules
   Family: Mach-O universal infostealer (curl | bash delivery, cloudproxy.link C2)

   Usage:
     yara -r yara_rules.yar /path/to/scanned/files

   Requires YARA 4.2+ for hash.sha256() in the exact-sample rule.
   Heuristic rules may false-positive on unrelated binaries that embed similar strings.
*/

import "hash"

rule HyperHives_MachO_Known_Malicious_SHA256 {
    meta:
        description = "Known malicious HyperHives campaign sample (Mach-O universal)"
        author = "Independent malware analysis repository"
        severity = "critical"
        malware_type = "infostealer"
        os = "darwin"
        date = "2026-04-06"
        hash_sha256 = "5c7385c3a4d919d30e81d851d87068dfcc4d9c5489f1c2b06da6904614bf8dd3"
        reference = "see repository README"
    condition:
        filesize < 12000000
        and filesize > 8000000
        and hash.sha256(0, filesize) == "5c7385c3a4d919d30e81d851d87068dfcc4d9c5489f1c2b06da6904614bf8dd3"
}

rule HyperHives_Config_C2_And_Sentry_Strings {
    meta:
        description = "Strong indicator: decrypted C2 + Sentry DSN strings from HyperHives analysis"
        author = "Independent malware analysis repository"
        severity = "high"
        malware_type = "infostealer"
        os = "darwin"
        date = "2026-04-06"
        reference = "see repository README"
    strings:
        $c2a = "cloudproxy.link/m/opened" ascii wide nocase
        $c2b = "cloudproxy.link/m/metrics" ascii wide nocase
        $c2c = "cloudproxy.link/m/decode" ascii wide nocase
        $c2d = "cloudproxy.link/db/debug" ascii wide nocase
        $sen = "ingest.de.sentry.io" ascii wide nocase
        $skey = "526eff9f8bb7aafd7117ca5e33a6a183" ascii wide
        $upld = "UPLD connect" ascii wide
    condition:
        filesize < 15000000
        and (uint32be(0) == 0xcafebabe or uint32(0) == 0xfeedfacf)
        and 2 of ($c2*)
        and $sen
        and $skey
        and $upld
}

rule HyperHives_Delivery_And_Protocol_Strings {
    meta:
        description = "Medium confidence: delivery domain + exfil protocol field names"
        author = "Independent malware analysis repository"
        severity = "medium"
        malware_type = "infostealer"
        os = "darwin"
        date = "2026-04-06"
        reference = "see repository README"
    strings:
        $h1 = "macos.hyperhives.net" ascii wide nocase
        $h2 = "hyperhives.net" ascii wide nocase
        $p1 = "build_namebuild_versionpers_password" ascii wide
        $p2 = "passwordswalletscreditsautofillsis_vm" ascii wide
        $p3 = "pers_password" ascii wide
        $t1 = "Documents/temp_data/Application" ascii wide
    condition:
        filesize < 15000000
        and (uint32be(0) == 0xcafebabe or uint32(0) == 0xfeedfacf)
        and 1 of ($h*)
        and 2 of ($p*)
        and $t1
}

rule HyperHives_Rust_Build_Path_Indicator {
    meta:
        description = "Weak signal: embedded Cargo path matching analyzed sample"
        author = "Independent malware analysis repository"
        severity = "low"
        malware_type = "infostealer"
        os = "darwin"
        date = "2026-04-06"
        reference = "see repository README"
    strings:
        $cargo = "/Users/rootr/.cargo/registry/" ascii wide
    condition:
        filesize < 15000000
        and (uint32be(0) == 0xcafebabe or uint32(0) == 0xfeedfacf)
        and $cargo
}
