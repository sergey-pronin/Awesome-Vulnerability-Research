# Awesome Vulnerability Research [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

## 🦄 A curated list of the awesome resources about the Vulnerability Research

> First things first:
> There are no exploits in this project. `Vulnerabilities != Exploits` A Vulnerability resides in the software itself, doing nothing on its own. If you are really curious about then you’ll find **your own way** to discover a flow, this list aimed to help you **find it faster**.

Maintained by [Serhii Pronin](https://github.com/re-pronin) with contributions from the [community](#thanks).
Become the next 🌟 [stargazer](https://github.com/re-pronin/Awesome-Vulnerability-Research/stargazers) or ✍️ [contributor](#contributing).  
In case of emergency [gimme a shout](mailto:serhii.pronin@protonmail.com) 🔑 [PGP key](http://pgp.mit.edu/pks/lookup?op=get&search=0x793A1A66A3418A12&lipi=urn%3Ali%3Apage%3Ad_flagship3_profile_view_base%3Br1HkkNzDR9KxXTBbMIYZRg%3D%3D) fingerprint: `2B56 34F1 51A3 84E0 A039 7815 793A 1A66 A341 8A12`

[![Made With Passion](https://img.shields.io/badge/made%20with-passion-red.svg)](https://github.com/re-pronin)
[![License CC-BY-SA-4.0](https://img.shields.io/badge/license-CC--BY--SA--4.0-green.svg)](#license)
[![GitHub Stars](https://img.shields.io/github/stars/re-pronin/Awesome-Vulnerability-Research.svg)](https://github.com/re-pronin/awesome-vulnerability-research/stargazers)

Vulnerability Research is the process of analyzing a product, protocol, or algorithm - or set of related products - to find, understand or exploit one or more vulnerabilities. Vulnerability research can but does not always involve reverse engineering, code review, static and dynamic analysis, fuzzing and debugging.

## Purpose

Currently, there is **way more** insecure code out there than researchers. Much more people looking at code that’s deployed in the real world are required by the market. This project exists to share a different awesome sources of information with you and encourage more people to get involved. Here you will find books and articles, online classes, recommended tools, write-ups, methodologies and tutorials, people to follow, and more cool stuff about Vulnerability Research and tinkering with application execution flow in general.

## Contributing

This List is published according to the *"Done is better than Perfect"* approach, so your contributions and suggestions are very valuable and are always welcome! There are two options:
1. Use the standard method of forking this repo, making your changes and [doing a pull request](https://github.com/re-pronin/Awesome-Vulnerability-Research/pulls) to have your content added. Please check the [Contributing Guideline](CONTRIBUTING.md) for more details.
2. Occasionally, if you just want to copy/paste your content, I'll take that too! [Create an "Issue"](https://github.com/re-pronin/Awesome-Vulnerability-Research/issues) with your suggestions and I will add it for you.

---
**Legend**:
* 🌟: Most Awesome
* 💰: Costs Money
* 🔥: Hot Stuff
* 🎁: For FREE
---
## Contents

* [Awesome Vulnerability Research](#awesome-vulnerability-research-)
* [Purpose](#purpose)
* [Contributing](#contributing)
* [Advisories](#advisories)
    - [Articles](#articles)
    - [Books](#books)
    - [Classes](#classes)
    - [Conferences](#conferences)
    - [Conference talks](#conference-talks)
    - [Intentionally vulnerable packages](#intentionally-vulnerable-packages)
    - [Mailing lists and Newsletters](#mailing-lists-and-newsletters)
    - [Presentations](#presentations)
    - [Podcasts and Episodes](#podcasts-and-episodes)
    - [Relevant Standards](relevant-standards)
    - [Research Papers](#research-papers)
        + [Whitepapers](#whitepapers)
        + [Individual researchers](#individual-researchers)
    - [Tools and Projects](#tools-and-projects)
        + [GitHub repos](#github-repos)
    - [Tutorials](#tutorials)
    - [Videos](#videos)
    - [Vendor’s bug databases](#vendors-bug-databases)
    - [Vulnerability databases](vulnerability-databases)
    - [Wargames and CTFs](#wargames-and-ctfs)
    - [Websites](#websites)
        + [Blogs](#blogs)
    - [Who to Follow](#who-to-follow)
    - [Miscellaneous Advisories](#miscellaneous-advisories)
* [Companies and Jobs](#companies-and-jobs)
* [Coordinated Disclosure](#coordinated-disclosure)
* [Common Lists](#common-lists)
    - [Awesome Lists](#awesome-lists)
    - [Other Lists](#other-lists)
* [Thanks](#thanks)
* [Glossary](GLOSSARY.md)  
* [License](#license)

## Advisories

[Back to Contents](#contents)

### Articles

* [Super Awesome Fuzzing, Part One](https://labsblog.f-secure.com/2017/06/22/super-awesome-fuzzing-part-one/) - by [Atte Kettunen](#twitter) and Eero Kurimo, 2017
* [From Fuzzing Apache httpd Server to CVE-2017-7668 and a $1500 Bounty](https://animal0day.blogspot.co.uk/2017/07/from-fuzzing-apache-httpd-server-to-cve.html) - by Javier Jiménez, 2017
*   [Root cause analysis of integer flow](https://www.corelan.be/index.php/2013/07/02/root-cause-analysis-integer-overflows/) - by [Corelan Team](#websites), 2013

[Back to Contents](#contents)

### Books
* 🌟[The Art of Software Security Assessment: Identifying and Preventing Software Vulnerabilities](https://www.amazon.com/Art-Software-Security-Assessment-Vulnerabilities/dp/0321444426) - by Mark Dowd, John McDonald, Justin Schuh - published 2006, ISBN-13: 978-0321444424 / ISBN-10: 9780321444424
* 🌟[The Shellcoder's Handbook: Discovering and Exploiting Security Holes](https://www.amazon.com/Shellcoders-Handbook-Discovering-Exploiting-Security/dp/047008023X/) - by Chris Anley, John Heasman, Felix Lindner, Gerardo Richarte - published 2007, 2nd Edition, ISBN-13: 978-0470080238 / ISBN-10: 047008023X

[Back to Contents](#contents)

### Classes
* [Advanced Windows Exploitation (AWE)](https://www.offensive-security.com/information-security-training/advanced-windows-exploitation/) - by Offensive Security with complementary OSEE (Offensive Security Exploitation Expert) Certification
* [Cracking The Perimeter (CTP)](https://www.offensive-security.com/information-security-training/cracking-the-perimeter/) - by Offensive Security, with complementary OSCE (Offensive Security Certified Expert) Certification
* 🎁[Modern Binary Exploitation (CSCI 4968)](https://github.com/RPISEC/MBE) - by RPISEC at Rensselaer Polytechnic Institute in Spring 2015. This was a university course developed and run solely by students to teach skills in vulnerability research, reverse engineering, and binary exploitation.
* [Software Security Course on Coursera](https://www.coursera.org/learn/software-security/) - by University of Maryland.
* [Offensive Computer Security](http://www.cs.fsu.edu/~redwood/OffensiveComputerSecurity/lectures.html) - by W. Owen Redwood and Prof. Xiuwen Liu.

[Back to Contents](#contents)

### Conferences

* 🌟[DEF CON](https://defcon.org/) - Las Vegas, NV, USA
* [Black Hat](https://www.blackhat.com/) - Las Vegas, NV, USA
* [Black Hat Europe](https://www.blackhat.com/upcoming.html) - London, UK //🔥Join [me](https://github.com/re-pronin) this year on [Dec 4-7, 2017](https://www.blackhat.com/eu-17/)!
* [Black Hat Asia](https://www.blackhat.com/upcoming.html) - Singapore
* 🎁[BSides](http://www.securitybsides.com/) - Worldwide //🔥Join [me](https://github.com/re-pronin) this year in [Warsaw](http://securitybsides.pl/) on [Oct 13-15, 2017](http://securitybsides.pl/)!
* [BruCON](http://brucon.org/) - Brussels, Belgium
* 🌟[Chaos Communication Congress (CCC)](https://www.ccc.de/en/) - Hamburg, Germany
* [Code Blue](https://codeblue.jp/) - Tokyo, Japan
* [Nullcon](http://nullcon.net/) - Goa, India
* [44CON](https://44con.com/) - London, UK
* [AppSecUSA](https://appsecusa.org/) - Washington DC 
* [OWASP AppSec EU](https://2017.appsec.eu/) - Europewide
* [Positive Hack Days](https://www.phdays.com/) - Moscow, Russia
* 🌟[ZeroNights](https://zeronights.org) - Moscow, Russia //🔥Join [me](https://github.com/re-pronin) this year on [Nov 16-17, 2017](https://2017.zeronights.org/)!
* 🌟[WarCon](http://warcon.pl/) - Warsaw, Poland

[Back to Contents](#contents)

### Conference talks

* 🌟[Vulnerabilities 101: How to Launch or Improve Your Vulnerability Research Game](https://www.youtube.com/watch?v=UYgBLUhHrCw) - by [Joshua Drake](#twitter) and [Steve Christey Coley](#twitter) at [DEFCON](#confernces) 24, 2016
* [Writing Vulnerability Reports that Maximize Your Bounty Payouts](https://www.youtube.com/watch?v=zyp2DoBqaO0) - by [Kymberlee Price](#twitter), originally presented at [Nullcon](#conferences), 2016
* [Browser Bug Hunting: Memoirs of a Last Man Standing](https://vimeo.com/109380793), by [Atte Kettunen](#twitter), presented at [44CON](#conferences), 2013

[Back to Contents](#contents)

### Intentionally vulnerable packages

* [HackSys Extreme Vulnerable Windows Driver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver)

[Back to Contents](#contents)

### Mailing lists and Newsletters

[Back to Contents](#contents)

### Presentations

* 🌟[Vulnerabilities 101: How to Launch or Improve Your Vulnerability Research Game [PDF]](https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20presentations/DEFCON-24-Drake-Christey-Vulnerabilities-101-UPDATED.pdf) - by [Joshua Drake](#twitter) and [Steve Christey Coley](#twitter) at [DEFCON](#confernces) 24, 2016
* 🌟[Effective File Format Fuzzing [PDF]](http://j00ru.vexillium.org/slides/2016/blackhat.pdf) - by [Mateusz “j00ru” Jurczyk](#twitter) presented at [BlackHat EU](#confernces), 2016
* [Bootstrapping A Security Research Project [PDF]](https://speakerd.s3.amazonaws.com/presentations/282c314b75404805b01825a73586ed27/Bootstrap_Research_-_SOURCEBoston2016.pdf) or [Speaker Deck](https://speakerdeck.com/andrewsmhay/source-boston-2016-bootstrapping-a-security-research-project) - by [Andrew M. Hay](#twitter) at SOURCE Boston, 2016
* [Bug Hunting with Static Code Analysis [PDF]](https://labs.mwrinfosecurity.com/assets/BlogFiles/mwri-bug-hunting-with-static-code-analysis-bsides-2016.pdf) - by Nick Jones, MWR Labs, 2016 

[Back to Contents](#contents)

### Podcasts and Episodes

#### Podcasts

[Back to Contents](#contents)

#### Episodes

[Back to Contents](#contents)

### Relevant Standards

* [CVE](https://cve.mitre.org/) - Common Vulnerabilities and Exposures, maintained by the [MITRE Corporation](https://www.mitre.org/)
* [CWE](https://cwe.mitre.org/) - Common Weakness Enumeration, maintained by the [MITRE Corporation](https://www.mitre.org/)
* [CVSS](https://www.first.org/cvss/) - Common Vulnerability Scoring System, maintained by [FIRST (Forum of Incident Response and Security Teams)](https://www.first.org/)

[Back to Contents](#contents)

#### Miscellaneous Documents

* 💰[ISO/IEC 29147:2014](https://www.iso.org/standard/45170.html) - Vulnerability Disclosure Standard
* [RFPolicy 2.0](https://dl.packetstormsecurity.net/papers/general/rfpolicy-2.0.txt) - Full Disclosure Policy (RFPolicy) v2.0 by [Packet Storm](https://packetstormsecurity.com/)

[Back to Contents](#contents)

### Research Papers

#### Whitepapers

* 🔥[TSIG Authentication Bypass Through Signature Forgery in ISC BIND [PDF]](http://www.synacktiv.ninja/ressources/CVE-2017-3143_BIND9_TSIG_dynamic_updates_vulnerability_Synacktiv.pdf) - Clément BERTHAUX, Synacktiv, [CVE-2017-3143](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-3143)

[Back to Contents](#contents)

#### Individual researchers

* 🔥[Taking Windows 10 Kernel Exploitation to the Next Level – Leveraging WRITE-WHAT-WHERE
Vulnerabilities in Creators Update [PDF]](https://github.com/MortenSchenk/BHUSA2017/blob/master/us-17-Schenk-Taking-Windows-10-Kernel-Exploitation-To-The-Next-Level%E2%80%93Leveraging-Write-What-Where-Vulnerabilities-In-Creators-Update-wp.pdf) - [Morten Schenk](#github), originally presented at [Black Hat](#conferences) 2017

[Back to Contents](#contents)

### Tools and Projects

* [Windbg](https://msdn.microsoft.com/en-in/library/windows/hardware/ff551063(v=vs.85).aspxi) - The preferred debugger by exploit writers.
* [ltrace](http://ltrace.org/) - Intercepts library calls 
* [ansvif](https://oxagast.github.io/ansvif/) - An advanced cross platform fuzzing framework designed to find vulnerabilities in C/C++ code.
* [Metasploit Framework](https://www.rapid7.com/products/metasploit/download.jsp) - A framework which contains some fuzzing capabilities via Auxiliary modules.
* [Spike](http://www.immunitysec.com/downloads/SPIKE2.9.tgz) - A fuzzer development framework like sulley, a predecessor of sulley.

[Back to Contents](#contents)

#### GitHub repos

* [Google Sanitizers](https://github.com/google/sanitizers) - A repo with extended documentation, bugs and some helper code for the AddressSanitizer, MemorySanitizer, ThreadSanitizer, LeakSanitizer. The actual code resides in the [LLVM](#l) repository.
* 🔥[FLARE VM](https://github.com/fireeye/flare-vm) -  FLARE (FireEye Labs Advanced Reverse Engineering) a fully customizable, Windows-based security distribution for malware analysis, incident response, penetration testing, etc.
* [hackers-grep](https://github.com/codypierce/hackers-grep) - The hackers-grep is a tool that enables you to search for strings in PE files. The tool is capable of searching strings, imports, exports, and public symbols (like woah) using regular expressions.
* [Grinder](https://github.com/stephenfewer/grinder) - Grinder is a system to automate the fuzzing of web browsers and the management of a large number of crashes. 
* [Choronzon](https://github.com/CENSUS/choronzon) - An evolutionary knowledge-based fuzzer 
* [boofuzz](https://github.com/jtpereyda/boofuzz) -  A fork and successor of Sulley framework
* [s a n d s i f t e r](https://github.com/re-pronin/sandsifter) - The x86 processor fuzzer


[Back to Contents](#contents)

### Tutorials

[Back to Contents](#contents)

### Videos

[Back to Contents](#contents)

### Vendor’s bug databases

* [Google Chrome issue tracker](https://bugs.chromium.org/p/chromium/issues/list) - The Chromium Project. *Google Account Required*

[Back to Contents](#contents)

### Vulnerability databases

[Back to Contents](#contents)

### Wargames and CTFs

[Back to Contents](#contents)

### Websites

* [Corelan Team](https://www.corelan.be/)
* [FuzzySecurity](http://www.fuzzysecurity.com/) by [b33f](who-to-follow)
* [Fuzzing Blogs](https://fuzzing.info/resources/) - by fuzzing.info

[Back to Contents](#contents)

#### Blogs

* 🌟[j00ru//vx tech blog](http://j00ru.vexillium.org/) - Coding, reverse engineering, OS internals covered one more time

[Back to Contents](#contents)

### Who to Follow

#### GitHub

* [FuzzySecurity](github.com/FuzzySecurity)
* [jksecurity](https://github.com/jksecurity)
* [MortenSchenk](https://github.com/MortenSchenk)

[Back to Contents](#contents)

#### Mastodon

[Back to Contents](#contents)

#### Medium

* the grugq [(@thegrugq)](https://medium.com/@thegrugq/)

[Back to Contents](#contents)

#### Slack

[Back to Contents](#contents)

#### SlideShare

[Back to Contents](#contents)

#### Speaker Deck

[Back to Contents](#contents)

#### Telegram

[Back to Contents](#contents)

#### Twitter

* 🌟Joshua Drake [(@jduck)](https://twitter.com/jduck)
* 🌟Steve Christey Coley [(@sushidude)](https://twitter.com/sushidude)
* Andrew M. Hay [(@andrewsmhay)](https://twitter.com/andrewsmhay)
* the grugq [(@thegrugq)](https://twitter.com/thegrugq)
* b33f [(@FuzzySec)](https://twitter.com/FuzzySec)
* Tim Strazzere [(@timstrazz)](https://twitter.com/timstrazz)
* Wojciech Pawlikowski [(@wpawlikowski)](https://twitter.com/wpawlikowski)
* Atte Kettunen [(@attekett)](https://twitter.com/attekett)
* Pawel Wylecial [(@h0wlu)](https://twitter.com/h0wlu)
* Hooked Browser [(@antisnatchor)](https://twitter.com/antisnatchor)
* Kymberlee Price [(@Kym_Possible)](https://twitter.com/Kym_Possible)
* Michael Koczwara [(@MichalKoczwara)](https://twitter.com/MichalKoczwara)
* Mateusz Jurczyk [(@j00ru)](https://twitter.com/j00ru)
* Project Zero Bugs [(@ProjectZeroBugs)](https://twitter.com/ProjectZeroBugs) - Cheks for new bug reports every 10 minutes. Not affiliated with Google.
* Hack with GitHub [(@HackwithGithub)](https://twitter.com/HackwithGithub) - Open source hacking tools for hackers and pentesters.

[Back to Contents](#contents)

### Miscellaneous Advisories

[Back to Contents](#contents)

## Companies and Jobs

[Back to Contents](#contents)

## Coordinated Disclosure

* [SecuriTeam Secure Disclosure (SSD)](https://www.beyondsecurity.com/ssd.html) - SSD provides the support you need to turn your experience uncovering security vulnerabilities into a highly paid career. SSD was designed by researchers, for researchers and will give you the fast response and great support you need to make top dollar for your discoveries.
* [The Zero Day Initiative (ZDI)](http://www.zerodayinitiative.com/) - ZDI is originally founded by TippingPoint, is a program for rewarding security researchers for responsibly disclosing vulnerabilities. Currently managed by Trend Micro.

[Back to Contents](#contents)

## Common Lists

### Awesome Lists

* [Awesome AppSec](https://github.com/paragonie/awesome-appsec) - A curated list of resources for learning about application security. Contains books, websites, blog posts, and self-assessment quizzes.
* [Awesome Web Security](https://github.com/qazbnm456/awesome-web-security) - A curated list of Web Security materials and resources.

[Back to Contents](#contents)

### Other Lists

* [Hack with Github](https://github.com/Hack-with-Github/Awesome-Hacking) - Open source hacking tools for hackers and pentesters.
* [Movies for Hackers](https://github.com/k4m4/movies-for-hackers) - A list of movies every cyberpunk must watch.
* [SecLists](https://github.com/danielmiessler/SecLists) - SecLists is the security tester's companion.

[Back to Contents](#contents)

## Thanks

* Joshua Drake [(@jduck)](https://twitter.com/jduck) and Steve Christey Coley [(@sushidude)](https://twitter.com/sushidude) for the inspiration!
* *@yournamehere* for the most awesome contributions
* And sure everyone of [you, who has sent the pull requests](https://github.com/re-pronin/Awesome-Vulnerability-Research/pulls) or [suggested](https://github.com/re-pronin/Awesome-Vulnerability-Research/issues) a link to add here!

Thanks a lot!

[Back to Contents](#contents)

## License

This work is licensed under a [Creative Commons Attribution Share-Alike 4.0 International License](LICENSE.md)

[![CC-BY-SA-4.0](https://mirrors.creativecommons.org/presskit/buttons/88x31/svg/by-sa.svg)](LICENSE.md)

[Back to Contents](#contents)
