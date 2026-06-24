# Real-World Subdomain Takeover Reports (Reference Database)

> Curated corpus of **real, publicly disclosed** subdomain takeover reports and resources, loaded from the internet to ground the hunting methodology in actual cases. Use for fingerprint patterns, provider behavior, impact calibration, and report writing.

## Corpus at a glance

- **167** detailed disclosed cases (method + PoC steps + verification) — see `real_reports.json` → `detailed_cases`
- **216** ranked HackerOne reports with live URLs, programs, upvotes, bounties — see `real_reports.json` → `ranked_hackerone_reports`
- **24** curated guides, fingerprint DBs, tools & writeups — table below
- **240 linkable real-report resources** total (132 cases carry a named vulnerable domain)

## Vulnerable services seen in the 167 detailed cases

| Service / Provider | Cases |
|---|---:|
| AWS S3 | 20 |
| AWS EC2 | 9 |
| Azure | 7 |
| AWS CloudFront | 7 |
| Unbounce | 6 |
| Fastly | 6 |
| Zendesk | 5 |
| Tumblr | 4 |
| Heroku | 4 |
| Webflow | 3 |
| AWS Route53 | 3 |
| UptimeRobot | 3 |
| Shopify | 3 |
| Netlify | 2 |
| UserVoice | 2 |
| GitLab Pages | 2 |
| Freshdesk | 2 |
| Squarespace | 2 |
| Wix | 2 |
| GitHub Pages | 2 |
| Modulus.io | 1 |
| Brandpad | 1 |
| Medium | 1 |
| GoDaddy domain service | 1 |
| Google services (GMAIL, Calendar, G-Drive, etc.) | 1 |
| Mashery | 1 |
| Hubspot | 1 |
| Instapage | 1 |
| [REDACTED] | 1 |
| GSuite (Google Apps) | 1 |
| Acquia Cloud | 1 |
| Discourse | 1 |
| Azure CDN | 1 |
| AWS | 1 |
| Uberflip | 1 |
| AWS Elastic IP | 1 |
| GitBook | 1 |
| WordPress | 1 |
| Vimeo | 1 |
| Vercel | 1 |
| statuspage.io | 1 |
| mozilla.org | 1 |
| Desk.com | 1 |
| kajabi | 1 |
| icn.bg mail service | 1 |
| SendGrid | 1 |
| FeedPress | 1 |
| Marketo | 1 |
| Azure Cloud Service | 1 |
| ghost.io | 1 |

**Takeaway:** AWS (S3 + EC2/Elastic-IP + CloudFront + Route53 ≈ 41 cases) dominates, followed by Azure, Fastly, Zendesk, Heroku, Tumblr, GitHub/GitLab Pages, Webflow, Shopify, Unbounce. Validate against `can-i-take-over-xyz` because several of these providers patched takeover over time.

## Most-affected programs (across 216 ranked reports)

| Program | Reports |
|---|---:|
| Mozilla | 18 |
| Mail.ru | 16 |
| Starbucks | 12 |
| Shopify | 11 |
| U.S. Dept Of Defense | 10 |
| X / xAI | 8 |
| 8x8 | 8 |
| HackerOne | 6 |
| Snapchat | 6 |
| Uber | 5 |
| Ubiquiti Inc. | 5 |
| GSA Bounty | 4 |
| Razer | 4 |
| OWOX, Inc. | 4 |
| Shipt | 3 |

## Top disclosed HackerOne reports (by community upvotes)

| ▲ | Bounty | Program | Title | Report |
|---:|---:|---|---|---|
| 778 | $0 | Roblox | Subdomain Takeover to Authentication bypass | https://hackerone.com/reports/335330 |
| 311 | $0 | Starbucks | Subdomain takeover of datacafe-cert.starbucks.com | https://hackerone.com/reports/665398 |
| 181 | $0 | Uber | Authentication bypass on auth.uber.com via subdomain takeover of saostatic.uber. | https://hackerone.com/reports/219205 |
| 162 | $1000 | Lyst | Subdomain takeover of storybook.lystit.com | https://hackerone.com/reports/779442 |
| 154 | $0 | HackerOne | Hacker.One Subdomain Takeover | https://hackerone.com/reports/159156 |
| 141 | $1000 | Grab | Subdomain Takeover Via Insecure CloudFront Distribution cdn.grab.com | https://hackerone.com/reports/352869 |
| 134 | $0 | HackerOne | Subdomain takeover at info.hacker.one | https://hackerone.com/reports/202767 |
| 128 | $0 | Shipt | Multiple Subdomain Takeovers: fly.staging.shipt.com, fly.us-west-2.staging.shipt | https://hackerone.com/reports/576857 |
| 122 | $0 | Starbucks | Subdomain takeover of mydailydev.starbucks.com | https://hackerone.com/reports/570651 |
| 122 | $0 | Starbucks | Subdomain takeover of d02-1-ag.productioncontroller.starbucks.com | https://hackerone.com/reports/661751 |
| 114 | $3000 | Snapchat | Subdomain takeover on http://fastly.sc-cdn.net/ | https://hackerone.com/reports/154425 |
| 109 | $0 | Starbucks | Subdomain takeover on svcgatewayus.starbucks.com | https://hackerone.com/reports/325336 |
| 105 | $0 | Starbucks | Subdomain takeover on happymondays.starbucks.com due to non-used AWS S3 DNS reco | https://hackerone.com/reports/186766 |
| 105 | $0 | Ford | Subdomain takeover on usclsapipma.cv.ford.com | https://hackerone.com/reports/484420 |
| 98 | $350 | Eternal | Subdomain takeover of fr1.vpn.zomans.com | https://hackerone.com/reports/1182864 |
| 95 | $500 | HackerOne | Subdomain takeover of resources.hackerone.com | https://hackerone.com/reports/863551 |
| 90 | $0 | Roblox | Subdomain Takeover at creatorforum.roblox.com | https://hackerone.com/reports/264494 |
| 89 | $0 | Starbucks | Subdomain takeover on wfmnarptpc.starbucks.com | https://hackerone.com/reports/388622 |
| 84 | $0 | Zego | Subdomain takeover of v.zego.com | https://hackerone.com/reports/1180697 |
| 83 | $0 | Starbucks | Multiple Subdomain takeovers via unclaimed instances | https://hackerone.com/reports/276269 |
| 81 | $0 | Paragon Initiative Enterprises | Subdomain Takeover | https://hackerone.com/reports/180393 |
| 79 | $0 | Uber | Subdomain takeover at signup.uber.com | https://hackerone.com/reports/197489 |
| 79 | $0 | Mozilla | Subdomain takeover on one of the subdomain under mozaws.net | https://hackerone.com/reports/2269867 |
| 79 | $0 | GitLab | Subdomain takeover in Gitlab pages | https://hackerone.com/reports/2523654 |
| 78 | $0 | HackerOne | Subdomain takeover #2  at info.hacker.one | https://hackerone.com/reports/209004 |
| 78 | $0 | IBM | Potential Subdomain Takeover on IBM.com domain. | https://hackerone.com/reports/3592387 |
| 77 | $0 | Bime | Subdomain takeover due to unclaimed Amazon S3 bucket on a2.bime.io | https://hackerone.com/reports/121461 |
| 77 | $0 | Basecamp | Subdomain Takeover due to ████████ NS records at us-east4.37signals.com | https://hackerone.com/reports/1342422 |
| 76 | $0 | Greenhouse.io | Subdomain Takeover on demo.greenhouse.io pointing to unbouncepages | https://hackerone.com/reports/407355 |
| 75 | $500 | Mozilla | Subdomain takeover on a subdomain under firefox.com | https://hackerone.com/reports/2899858 |
| 75 | $0 | Flock | Subdomain takeover dew to missconfigured project settings for Custom domain . | https://hackerone.com/reports/428651 |
| 74 | $50 | Omise | Subdomain takeover http://accessday.opn.ooo/ | https://hackerone.com/reports/1963213 |
| 73 | $750 | Shipt | Subdomain Takeover at test.shipt.com | https://hackerone.com/reports/387760 |
| 71 | $0 | Shopify | myshopify.com domain takeover | https://hackerone.com/reports/320355 |
| 71 | $0 | X / xAI | Subdomain takeover of images.crossinstall.com | https://hackerone.com/reports/1406335 |
| 70 | $100 | Acronis | Subdomain takeover of main domain of https://www.cyberlynx.lu/ | https://hackerone.com/reports/1256389 |
| 69 | $0 | Uber | Subdomain takeover on rider.uber.com due to non-existent distribution on Cloudfr | https://hackerone.com/reports/175070 |
| 67 | $500 | Shopify | Subdomain Takeover Via unclaimed Heroku Instance tim-exclusive.shopify.com | https://hackerone.com/reports/424669 |
| 66 | $500 | Mozilla | [ addons-preview-cdn.mozilla.net ] A subdomain takeover is available via unregis | https://hackerone.com/reports/2706358 |
| 62 | $250 | Kubernetes | Subdomain Takeover Via via Dangling NS records on Amazon Route 53 http://api.e2e | https://hackerone.com/reports/746000 |
| 62 | $0 | U.S. Dept Of Defense | Subdomain takeover ████████.mil | https://hackerone.com/reports/2499178 |
| 61 | $0 | Eternal | subdomain takeover on fddkim.zomato.com | https://hackerone.com/reports/1130376 |
| 61 | $0 | Zenly | Subdomain Takeover of brand.zen.ly | https://hackerone.com/reports/1474784 |
| 60 | $0 | Mars | Bug Report #23JAN136 (subdomain takeover via shopify ) | https://hackerone.com/reports/1851895 |
| 59 | $0 | RATELIMITED | Subdomain takeover in GitLab Pages [george.ratelimited.me] | https://hackerone.com/reports/2523677 |
| 58 | $0 | HackerOne | Subdomain takeover #3 at info.hacker.one | https://hackerone.com/reports/217358 |
| 57 | $0 | Ubiquiti Inc. | Subdomain takeover on partners.ubnt.com due to non-used CloudFront DNS entry | https://hackerone.com/reports/145224 |
| 55 | $500 | Affirm | Subdomain takeover of www█████████.affirm.com | https://hackerone.com/reports/1297689 |
| 55 | $0 | X / xAI | Subdomain takeover on dev-admin.periscope.tv | https://hackerone.com/reports/531890 |
| 54 | $0 | Ubiquiti Inc. | Authentication bypass on sso.ubnt.com via subdomain takeover of ping.ubnt.com | https://hackerone.com/reports/172137 |
| 53 | $0 | U.S. Dept Of Defense | Subdomain takeover ██████ | https://hackerone.com/reports/2552243 |
| 51 | $0 | Starbucks | Subdomain takeover on developer.openapi.starbucks.com | https://hackerone.com/reports/275714 |
| 50 | $0 | X / xAI | URGENT - Subdomain Takeover on media.vine.co due to unclaimed domain pointing to | https://hackerone.com/reports/32825 |
| 50 | $0 | HackerOne | Subdomain takeover #4 at info.hacker.one | https://hackerone.com/reports/220002 |
| 50 | $0 | Mozilla | Subdomain takeover on one of the subdomains under mozaws.net | https://hackerone.com/reports/2545012 |
| 49 | $0 | Mars | Bug Report #23JAN135 (subdomain takeover via shopify ) | https://hackerone.com/reports/1851886 |
| 48 | $0 | Affirm | Subdomain takeover due to non registered TLD [ ██████████.█████.██████.com ] | https://hackerone.com/reports/1312365 |
| 48 | $0 | Mozilla | Subdomain takeover on one of the subdomain under mozaws.net | https://hackerone.com/reports/2131215 |
| 47 | $0 | Basecamp | Domain Takeover [3737signals.com] | https://hackerone.com/reports/1253926 |
| 47 | $0 | Smule | Possible Subdomain Takeover For Inbound Emails | https://hackerone.com/reports/2567048 |

*Full list of all 216 ranked reports is in `real_reports.json`.*

## Notable detailed cases (method + verification captured)

- **api.legalrobot.com** — *Modulus.io* (n/a). The subdomain api.legalrobot.com was pointed via DNS to Modulus.io, but no application was deployed on Modulus for that domain, resulting in a dangling DNS entry. The attacker created an account on Modulus.io and claimed the wildcard domain
- **brand.zen.ly** — *Brandpad* (CNAME-based). The subdomain brand.zen.ly was pointing via a CNAME record to brandpad.io, a service that allows users to register and claim custom domains. The attacker registered an account on Brandpad and added brand.zen.ly as a custom domain, thereby t
- **datacafe-cert.starbucks.com** — *Azure* (CNAME-based). The subdomain had a dangling CNAME record pointing to an unclaimed Azure webservice domain. The attacker registered the Azure webservice with the target name, thereby gaining full control over the subdomain datacafe-cert.starbucks.com.
- **info.hacker.one** — *Unbounce* (n/a). The attacker claimed the subdomain by creating a new page in the Unbounce Pages app under the vulnerable endpoint, modifying the page's domain parameter to point to any domain they control, effectively allowing full takeover of the subdomai
- **badootech.badoo.com** — *Medium* (n/a). The subdomain badootech.badoo.com was pointing to Medium servers, allowing an attacker to take over the subdomain by claiming the Medium blog associated with that subdomain, enabling control over the content served on that domain.
- **saostatic.uber.com** — *AWS CloudFront* (CNAME-based). The subdomain saostatic.uber.com was pointing to an AWS Cloudfront CDN hostname that was no longer registered or controlled by Uber, allowing the attacker to fully takeover the domain by serving content from their own webserver over HTTP an
- **[REDACTED].mil** — *GoDaddy domain service* (CNAME-based). The subdomain pointed via a CNAME record to a target domain (peosol-lg.[REDACTED]) that was unclaimed or expired on GoDaddy, allowing an attacker to register the target domain and serve content under the original subdomain.
- **moderator.ubnt.com** — *—* (CNAME-based). The attacker claimed the abandoned subdomain by registering it to their own account, thereby fully taking over the subdomain and gaining control over it. This was possible because the subdomain was pointing via a CNAME record to an unclaime
- **www[REDACTED].affirm.com** — *AWS S3* (n/a). The subdomain www[REDACTED].affirm.com pointed to a non-existent AWS S3 bucket (affirm-prod-www-cms[REDACTED]). The attacker was able to create and control this S3 bucket, upload arbitrary content, and serve it via the subdomain, effectivel
- **[REDACTED]** — *AWS S3* (n/a). Claimed the unclaimed Amazon S3 bucket that the subdomain pointed to, which no longer existed, thereby taking control of the subdomain by hosting content on the newly claimed S3 bucket.
- **[REDACTED].[REDACTED].[REDACTED].com** — *—* (CNAME-based). The subdomain pointed via a CNAME record to a non-registered top-level domain (TLD). An attacker can register the unregistered TLD and create the corresponding domain and subdomain to serve content on the vulnerable subdomain, effectively t
- **www.jet.acronis.com** — *Webflow* (n/a). Registering a Webflow account, upgrading to a paid plan to enable custom domain setup, then adding the vulnerable subdomain (www.jet.acronis.com) as a custom domain in Webflow hosting settings, allowing the attacker to serve content on the 
- **blog.snapchat.com** — *Tumblr* (ANAME-based). The ANAME record for blog.snapchat.com pointed to snapchat-blog.com, which was configured as a custom domain on Tumblr. Since the Tumblr blog had expired or removed the CNAME claim, adding snapchat-blog.com to the custom domain setting on T
- **api.e2e-kops-aws-canary.test-cncf-aws.canary.k8s.io** — *AWS Route53* (NS-based). Exploiting dangling NS records on Amazon Route 53 by registering the subdomain's name servers under attacker's control, allowing the attacker to serve content and receive emails for the subdomain.
- **█.easycontactnow.com** — *Zendesk* (CNAME-based). The subdomain's CNAME record pointed to an abandoned Zendesk instance outside of 8x8's control, allowing potential takeover by claiming the abandoned service.
- **tim-exclusive.shopify.com** — *Heroku* (n/a). The subdomain was pointing to an unclaimed Heroku instance, allowing an attacker to claim the Heroku app and gain control over the subdomain.
- **███.wavecell.com** — *AWS S3* (n/a). An S3 bucket was deleted, but a DNS record pointing to the bucket was not updated or removed, allowing potential subdomain takeover.
- **['translate.uber.com', 'fr.uber.com', 'de.uber.com']** — *—* (CNAME-based). Subdomains were pointing to a CNAME for a site that was not claimed. The attacker claimed the target site and was able to add any content, effectively taking over the subdomain.
- **developer.openapi.starbucks.com** — *Mashery* (n/a). Registered a trial account on Mashery, then added the vulnerable subdomain developer.openapi.starbucks.com as a custom domain in Mashery's portal settings, allowing serving custom content on that subdomain without verification or error.
- **[REDACTED]** — *Azure* (CNAME-based). The subdomain pointed via a CNAME record to an unclaimed domain on Azure. The attacker claimed the unclaimed Azure domain and hosted a proof-of-concept file, effectively taking over the subdomain.
- **blog.greenhouse.io** — *Hubspot* (CNAME-based). The subdomain blog.greenhouse.io pointed via a CNAME record to Hubspot, but the Hubspot account was expired or cancelled. This allowed an attacker to claim the subdomain on Hubspot and serve arbitrary content, effectively taking over the su
- **['bugs.instacart.com', 'atlas.instacart.com']** — *Heroku* (CNAME-based). Subdomains pointed via CNAME DNS records to Heroku apps that were unconfigured or non-existent, allowing an attacker to claim the Heroku app and take over the subdomain.
- **http://██.get8x8.com/** — *Netlify* (CNAME-based). Subdomain takeover was achievable due to a misconfiguration of a Netlify target, allowing an attacker to claim the dangling CNAME and serve content on the subdomain.
- **ux.shopify.com** — *Tumblr* (CNAME-based). The subdomain ux.shopify.com was pointing via a CNAME record to domains.tumblr.com, but the subdomain was not claimed by any Tumblr user. An attacker could register a Tumblr blog using this subdomain, effectively taking over the subdomain a
- **hacker.one** — *Instapage* (CNAME-based). The subdomain takeover was achieved by exploiting a 0day issue in Instapage where the hacker was able to claim the subdomain via a CNAME pointing to Instapage, allowing them to serve arbitrary content on the official hacker.one domain.

*All 167 cases with full PoC steps & verification are in `real_reports.json` → `detailed_cases`.*

## Curated guides, fingerprint DBs, tools & writeups

| Category | Resource | Link |
|---|---|---|
| Fingerprint DB | can-i-take-over-xyz (EdOverflow) — Canonical service fingerprint database — is each provider takeoverable today? | https://github.com/EdOverflow/can-i-take-over-xyz |
| Fingerprint DB | can-i-take-over-dns (indianajson) — NS/DNS-provider takeover fingerprint database. | https://github.com/indianajson/can-i-take-over-dns |
| Guide | A Guide To Subdomain Takeovers 2.0 — HackerOne — HackerOne's updated methodology guide. | https://www.hackerone.com/blog/guide-subdomain-takeovers-20 |
| Guide | OWASP WSTG — Test for Subdomain Takeover — OWASP testing methodology. | https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover |
| Guide | Hostile subdomain takeover using Heroku/Github/Desk — Detectify Labs — Foundational Detectify research on SaaS takeovers. | https://labs.detectify.com/writeups/hostile-subdomain-takeover-using-heroku-github-desk-more/ |
| Guide | Subdomain Takeover: Proof Creation — Patrik Hudak — Safe proof-of-control creation for bug bounties. | https://0xpatrik.com/takeover-proofs/ |
| Guide | Threat tactic spotlight: Subdomain takeover — AWS Security Blog — AWS detection/remediation for dangling CNAMEs to S3/CloudFront. | https://aws.amazon.com/blogs/security/threat-tactic-spotlight-subdomain-takeover/ |
| Analysis | What I learnt from reading 217 Subdomain Takeover bug reports — BrownBearSec — Meta-analysis of 217 disclosed reports. | https://medium.com/@BrownBearSec/what-i-learnt-from-reading-217-subdomain-takeover-bug-reports-c0b94eda4366 |
| Dataset | yee-yore LLM-Context subdomain_takeover.json (167 cases) — 167 detailed disclosed HackerOne cases (source of real_reports.json). | https://github.com/yee-yore/LLM-Context/blob/main/vulnerabilities/subdomain_takeover.json |
| Dataset | reddelexc hackerone-reports — TOPSUBDOMAINTAKEOVER — 216 top disclosed H1 takeover reports w/ bounties. | https://github.com/reddelexc/hackerone-reports/blob/master/docs/tops_by_bug_type/TOPSUBDOMAINTAKEOVER.md |
| Tool | tko-subs (anshumanbh) — Automated subdomain takeover detection. | https://github.com/anshumanbh/tko-subs |
| Tool | takeovflow (theoffsecgirl) — Takeover hunting workflow tool. | https://github.com/theoffsecgirl/takeovflow |
| Tool | aws-samples/sample-dangling-dns-detection — AWS Config rule for dangling DNS detection. | https://github.com/aws-samples/sample-dangling-dns-detection |
| Writeup | Subdomain Takeover in Azure: making a PoC — GoDiego — Step-by-step Azure azurewebsites/cloudapp PoC. | https://diego95root.github.io/posts/STO-Azure/ |
| Writeup | 10K Site Affected? Subdomain Takeover via lemlist — KreSec — Mass SaaS custom-domain takeover via lemlist. | https://kresec.medium.com/10k-site-affected-subdomain-takeover-via-lemlist-146cd0f11883 |
| Writeup | How I got a $5000 Bounty from Microsoft — Bashir Mohamed — Microsoft subdomain bug, $5k bounty. | https://medium.com/@bashir69emceeaka5/how-i-got-a-5000-bounty-from-microsoft-fb2e27fd40f7 |
| Writeup | AWS S3 Bucket Takeover — Vidoc Security — Find & maximize impact of S3 bucket takeover. | https://blog.vidocsecurity.com/blog/aws-s3-bucket-takeover |
| Writeup | Wasabi Bucket Takeover — OSINT Team — Object-storage takeover beyond AWS. | https://osintteam.blog/wasabi-bucket-takeover-bug-bounty-7520e8decde7 |
| Writeup | The Bucket You Deleted is Still in Your DNS (Bime) — dev.to — Real S3 dangling-DNS takeover walkthrough. | https://dev.to/bala_paranj_059d338e44e7e/the-bucket-you-deleted-is-still-in-your-dns-s3-bucket-takeover-at-bime-256j |
| Writeup | Hunting Dangling DNS in AWS (2026) — JSMON — Updated AWS Elastic IP / CloudFront / S3 techniques. | https://blogs.jsmon.sh/hunting-dangling-dns-how-to-exploit-aws-elastic-ips-cloudfront-and-s3/ |
| News | WatchTowr: abandoned S3 buckets pose supply-chain risk — TechTarget — Real-world mass abandoned-bucket research. | https://www.techtarget.com/searchsecurity/news/366618663/WatchTowr-warns-abandoned-S3-buckets-pose-supply-chain-risk |
| Guide | The Ultimate Guide for Subdomain Takeover (Exploit-DB) — Touhid M. Shaikh — Practical PoC guide PDF. | https://www.exploit-db.com/docs/english/46415-the-ultimate-guide-for-subdomain-takeover-with-practical.pdf |
| Guide | Mastering Subdomain Takeover — Very Lazy Tech — End-to-end takeover methodology. | https://medium.verylazytech.com/mastering-subdomain-takeover-48d9b9d593a9 |
| Guide | Subdomain Takeover: Complete Technical Guide — SixHack Academy — Technical guide with provider specifics. | https://sixhackacademy.com/en/blog/subdomain-takeover/ |

## How to use this corpus

1. **Detection** — match enrichment output (CNAME target + HTTP/TLS fingerprint) against the service patterns above and `can-i-take-over-xyz` before flagging a candidate.
2. **Validation** — many providers (Azure App Service, GitHub Pages, Heroku, Shopify) added domain-verification and are *no longer* takeoverable; confirm current behavior per case, don't trust age-old PoCs.
3. **Impact calibration** — the Roblox/Uber auth-bypass and Snapchat ($3k) cases show how a takeover on a cookie-scoped or auth subdomain escalates to account takeover; weight severity accordingly.
4. **Reporting** — mirror the disclosed reports' structure: DNS evidence → service fingerprint → safe proof → realistic impact (see `references/templates.md`).
