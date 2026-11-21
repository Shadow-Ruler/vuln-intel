"""Hand-written sample documents in each source's real format. All data is fictional."""
import gzip
import json

CVE_RECORD = {
    "dataType": "CVE_RECORD",
    "dataVersion": "5.2",
    "cveMetadata": {
        "cveId": "CVE-2099-10001", "assignerShortName": "example", "state": "PUBLISHED",
        "datePublished": "2099-01-02T10:00:00.000Z", "dateUpdated": "2099-01-03T11:22:33.456Z",
    },
    "containers": {
        "cna": {
            "title": "Heap overflow in the HTTP/2 frame parser",
            "descriptions": [
                {"lang": "es", "value": "Desbordamiento"},
                {"lang": "en", "value": "A crafted frame‮ overflows a heap buffer.\x00"},
            ],
            "affected": [{
                "vendor": "F5", "product": "NGINX Open Source", "defaultStatus": "unaffected",
                "cpes": ["cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"],
                "versions": [
                    {"version": "1.9.5", "lessThan": "1.30.7", "status": "affected", "versionType": "semver"},
                    {"version": "1.31.0", "lessThan": "1.31.9", "status": "affected", "versionType": "semver"},
                ],
            }],
            "metrics": [
                {"other": {"type": "vendor rating", "content": {"value": "Critical"}}},
                {"cvssV3_1": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                 "format": "CVSS"},
            ],
            "problemTypes": [{"descriptions": [{"cweId": "CWE-122", "lang": "en"}]}],
            "references": [
                {"url": "https://example.com/advisory/1"},
                {"url": "javascript:alert(1)"},
            ],
        },
        "adp": [
            {
                "providerMetadata": {"shortName": "CISA-ADP"},
                "title": "CISA ADP Vulnrichment",
                "metrics": [
                    {"other": {"type": "ssvc", "content": {"options": [
                        {"Exploitation": "active"}, {"Automatable": "yes"}, {"Technical Impact": "total"},
                    ]}}},
                    {"other": {"type": "kev", "content": {"dateAdded": "2099-01-04"}}},
                ],
            },
            {"providerMetadata": {"shortName": "CVE"}, "references": []},
        ],
    },
}

KEV = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": "2099.01.04",
    "dateReleased": "2099-01-04T17:00:00.0000Z", "count": 2,
    "vulnerabilities": [
        {"cveID": "CVE-2099-10001", "vendorProject": "F5", "product": "NGINX",
         "vulnerabilityName": "F5 NGINX Heap Overflow Vulnerability", "dateAdded": "2099-01-04",
         "shortDescription": "x", "requiredAction": "y", "dueDate": "2099-01-25",
         "knownRansomwareCampaignUse": "Unknown", "notes": "", "cwes": ["CWE-122"]},
        {"cveID": "not-a-cve", "vendorProject": "Bad", "product": "Entry", "dateAdded": "2099-01-04"},
    ],
}

EPSS_CSV = (
    "#model_version:v2099.01.01,score_date:2099-01-04T00:00:00+0000\n"
    "cve,epss,percentile\n"
    "CVE-2099-10001,0.91234,0.99100\n"
    "CVE-2099-10002,0.10000,0.85000\n"
    "CVE-2099-10003,0.00100,0.20000\n"
    "garbage,0.5,0.99\n"
)
EPSS_GZ = gzip.compress(EPSS_CSV.encode())

GHSA = [{
    "ghsa_id": "GHSA-cmxg-94mg-jq94", "cve_id": "CVE-2099-10002",
    "summary": "Deserialization flaw in example-lib", "severity": "high",
    "published_at": "2099-01-02T17:07:04Z", "updated_at": "2099-01-03T17:07:04Z", "withdrawn_at": None,
    "vulnerabilities": [
        {"package": {"ecosystem": "composer", "name": "example/lib"},
         "vulnerable_version_range": "< 2.3.1", "first_patched_version": "2.3.1", "vulnerable_functions": []},
        {"package": {"ecosystem": "maven", "name": "org.example:lib"},
         "vulnerable_version_range": "< 9.0.0", "first_patched_version": None},
    ],
}]

HN = {
    "hits": [
        {"objectID": "4242", "title": "Nginx2Shell: unauthenticated RCE in HTTP/2 (CVE-2099-10001)",
         "url": "https://example.org/nginx2shell", "created_at": "2099-01-04T09:00:00Z"},
        {"objectID": "4243", "title": "Ask HN: how do you patch PHP?", "url": None,
         "created_at": "2099-01-04T09:05:00Z"},
        {"objectID": "nope", "title": "No URL and a bad id", "url": None},
    ],
    "nbHits": 3,
}

RSS = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/">
 <channel>
  <title>Example Security Blog</title>
  <item>
   <title><![CDATA[Critical flaw dubbed PHPGhost hits PHP <b>servers</b>]]></title>
   <link>https://blog.example.com/phpghost</link>
   <pubDate>Fri, 04 Jan 99 12:00:00 +0000</pubDate>
   <description>Tracked as cve-2099-10002 and CVE-2099-10003.</description>
  </item>
  <item>
   <title>No link here</title>
  </item>
 </channel>
</rss>"""

ATOM = b"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
 <entry>
  <title>PHP 8.3.36 released</title>
  <link rel="alternate" href="https://www.php.net/releases/8_3_36.php"/>
  <link rel="via" href="https://www.php.net/other"/>
  <published>2099-01-04T14:00:00+00:00</published>
  <content type="html">Security release.</content>
 </entry>
</feed>"""

RDF = b"""<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/"
         xmlns:dc="http://purl.org/dc/elements/1.1/">
 <item rdf:about="https://www.debian.org/security/2099/dsa-9001">
  <title>DSA-9001 nginx - security update</title>
  <link>https://www.debian.org/security/2099/dsa-9001</link>
  <dc:date>2099-01-04</dc:date>
 </item>
</rdf:RDF>"""

ENTITY_BOMB = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">]>
<rss><channel><item><title>&lol2;</title><link>https://x.example/</link></item></channel></rss>"""

DELTA_LOG = [
    {"fetchTime": "2099-01-04T10:07:00.000Z", "numberOfChanges": 2,
     "new": [{"cveId": "CVE-2099-10001", "dateUpdated": "2099-01-04T10:00:00.000Z"}],
     "updated": [{"cveId": "CVE-2099-0462"}], "error": []},
    {"fetchTime": "2099-01-04T09:00:00.000Z", "numberOfChanges": 1,
     "new": [{"cveId": "CVE-2099-10000"}], "updated": [], "error": []},
    {"fetchTime": "2099-01-04T11:00:00.000Z", "numberOfChanges": 2,
     "new": [{"cveId": "../../etc/passwd"}, {"cveId": "CVE-2099-123456"}], "updated": [], "error": []},
]


def dumps(obj) -> bytes:
    return json.dumps(obj).encode()
