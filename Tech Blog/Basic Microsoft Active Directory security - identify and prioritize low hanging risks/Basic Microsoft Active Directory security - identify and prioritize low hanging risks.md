![[cover-pingcastle-100.png]]
# Basic Microsoft Active Directory security - identify and prioritize low hanging risks

Securing Microsoft Active Directory (AD) is essential for most businesses’ operations, as AD is the backbone of user access and authentication. In mainstream media the most infamous threat is ransomware shutting down businesses for weeks; this is almost always because an AD was compromised by an attacker.

Even though the threat seems imminent, in my experience, many system administrators are unable to identify, prioritize, and address security risks in their AD. It could be due to Microsoft's lengthy and often overwhelming documentation, or simply due to a lack of awareness of how easily it can be done.

In this post, I will provide system administrators with a starting point for securing their AD; how to identify and prioritize low hanging security risks in AD.

However, this is just the beginning and does not cover Azure AD.
I also recommend getting input from security professionals, for example through Improsec's [Active Directory Security Analysis](https://improsec.com/en/active-directory-security-analysis); a complete analysis that:
* Provides an executive summary for management and decision makers
* Identifies many more security risks
	* Both technical and procedural risks (this post is mostly regarding technical risks)
	* Goes beyond theory by demonstrating the effects of the risks (executive decisions and budgets are often more "sensible" if a domain compromise is demonstrated)
	* Goes beyond common AD security risks (some of Improsec's internal recommendations are not described publicly)
* Gives tangible recommendations to address the risks

I have tried to keep this post simple by recommending:
* Using an AD security analysis tool
* Implementing three "simple" but effective practices that the tools will not recommend

## Active Directory security analysis tool
Run one of these tools:
* PingCastle - https://pingcastle.com/
	* Has attack/control path analysis capabilities similar to [BloodHound](https://github.com/BloodHoundAD/BloodHound)
	* Run with `.\PingCastle.exe --healthcheck`
* Purple Knight - https://www.purple-knight.com/
	* No control path analysis capabilities. Should be used in tandem with [BloodHound](https://github.com/BloodHoundAD/BloodHound)
	* Run by double-clicking `PurpleKnight.exe`.

Run them as a regular Domain User from a domain-joined system. They may be detected as malware as attackers use them too. Who runs them fist? You, or the adversary?

The tools will identify and prioritize many generic risks and will help you addressing them by giving basic recommendations or linking to technical resources.
You can prioritize addressing the risks based on their reported criticality but be aware that the criticality is not always correct.
For example a PingCastle report at a customer had the two findings:
1. "*Unconstrained delegations are configured on the domain: 10 account(s)*" (P-UnconstrainedDelegation)
	* This scored 50 points.
2. "*Everyone can take control of a key domain object by abusing targeted permissions.*" (P-ControlPathIndirectEveryone)
	* This scored 25 points (a lower risk than 50 points).
	* In practice this risk was much higher than the unconstrained delegations.

Therefore I have attempted to list what I consider low hanging risks (often easy to fix, potentially high risks).
In a PingCastle report, expand its findings and look for "Rule ID". Focus on addressing these:
* S-NoPreAuth
* S-NoPreAuthAdmin
* S-PwdNotRequired
* S-SMB-v1
* S-Vuln-MS14-068
* S-Vuln-MS17_010
* S-DC-NotUpdated
* P-DelegationLoginScript
* P-DelegationFileDeployed
* P-DelegationGPOData
* P-LoginDCEveryone
* P-ControlPathIndirectEveryone
* P-DelegationEveryone
* A-MembershipEveryone
* A-LAPS-Joined-Computers
* A-DC-Spooler
* A-DC-WebClient
* A-UnixPwd
* A-PwdGPO
* The presence of these can be OK, but some combinations of them are high risks:
	* A-CertTempCustomSubject
	* A-CertTempNoSecurity
	* A-CertEnrollHttp
	* A-CertTempAnyone
	* A-CertEnrollChannelBinding
	* A-CertTempAgent
	* A-CertTempAnyPurpose

If you use Purple Knight, you should be able to correlate [Purple Knight Indicators](https://www.purple-knight.com/security-indicators/) to [Ping Castle Rules](https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html) quite easily.

Improsec uses such automation tools in our [Active Directory Security Analysis](https://improsec.com/en/active-directory-security-analysis), but as stated in the introduction, our comprehensive analysis goes beyond automated tools and their basic recommendations.
If needed, Improsec can assist in prioritizing and addressing any AD risks through [Active Directory security hardening](https://improsec.com/en/ad-security-hardening).

`Footnote: I often spend time on reporting exactly what these tools report. I don't want to do that; I would like complex tasks. Just run the basic tools yourself.`

## Practice 1 - Eliminate over-permissive network shares ACLs
You should identify and remove over-permissive network shares.
These are any that are readable, or writeable, to large groups of users i.e. `Domain Users`, `Authenticated Users`, or `Everyone`.

You: "*But I don't have such in my AD!*"
Me: "*Yes you do.*"

The most basic risks are:
* Domain-wide **readable** shares containing sensitive data (scripts, backups, IT documentation)
* Domain-wide **writeable** shares containing executable files (scripts, applications, deployments like WSUS and SCCM)

Identify the risks with one of these tools:
* [PowerHuntShares](https://github.com/NetSPI/Powerhuntshares)
* [SMBeagle](https://github.com/punk-security/smbeagle)

Lastly, reduce likelihood of new over-permissive ACLs. Deploy the secure network share default explained in the section ***Changing default Windows share permissions*** of by post: [Network share risks](https://improsec.com/tech-blog/network-share-risks-deploying-secure-defaults-and-searching-shares-for-sensitive-information-credentials-pii-and-more).

If needed, Improsec can implement secure network share defaults, and perform a [comprehensive network shares security analysis](https://improsec.com/en/network-shares-security-analysis).

`Footnote: I often find a domain-wide readable share containing a Domain Admins password, or with terabytes of ERP data. I don't want to do that; I would like complex tasks. Just scan for the obvious shares yourself.`

## Practice 2 - Secure passwords
This practice is split in two.

**Ensure a secure password length**
Set a secure minimum length for all AD accounts:
* All accounts should have at minimum 16 characters, complexity not required.
* Any account with a service principal name (SPN) should at minimum have a 50-character password.
	* In scope are **all** (yes, all!) accounts returned by this command: `Get-ADUser -Filter '(servicePrincipalName -like "*") -and (Enabled -eq $True)'`
	* Some applications may not support 64 characters. In such case use as long a password as possible.

Use Fine-Grained Password Policies to enforce a differential password policy, [read more here](https://www.linkedin.com/pulse/protect-active-directory-users-from-password-attacks-b%C3%BClow-knudsen).

**Eliminate bad passwords**
You should ensure that:
* No account use passwords known by [have I been pwned?](https://haveibeenpwned.com/) or similar large, compromised password lists.
* No accounts use weak passwords (e.g. `CompanyName2023`).
* No two accounts share the same password.

This can be achieved with the tools below. I recommend at minimum implementing Get-bADpasswords and Azure AD Password Protection without the DC Agent.
| Tool                                       | On-premises users | Azure users | Detects password sharing | Detects existing weak passwords | Prevents new weak passwords | Notes                                                                                    |
|--------------------------------------------|:-------------------------------------------------:|:-------------------:|:------------------------:|:----------------------:|:---------------------------:|------------------------------------------------------------------------------------------|
| [Get-bADpasswords](https://github.com/improsec/Get-bADpasswords)                           | Yes                                               | -                   | Yes                      | Yes                    | -                           | Created by Improsec                                                                      |
| [IPA](https://github.com/improsec/ImprosecPasswordAuditor)                                        | Yes                                               | -                   | Yes                      | Yes                    | -                           | Created by Improsec. Less customizable than Get-bADpasswords                             |
| [DSInternals](https://www.dsinternals.com/en/auditing-active-directory-password-quality/)                                | Yes                                               | -                   | Yes                      | Yes                    | -                           | Inspired by Improsec's Get-bADpasswords                                                  |
| [IPF](https://github.com/improsec/ImprosecPasswordFilter)                                        | Yes                                               | -                   | -                        | -                      | Yes                         | Can be combined with Get-bADpasswords, IPA, or DSInternals. Must be installed on all DCs |
| [Azure AD Password Protection](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-password-ban-bad) | Yes, if using DC Agent                            | Yes                 | -                        | -                      | Yes                         | Has a smaller compromised password list than the other tools                             |

The above tools only secure AD accounts. You must also consider non-AD accounts, such as local administrator accounts of AD joined systems. I will return to this topic in Practice 3...

If needed, Improsec can assist in securing passwords, and perform a [comprehensive Active Directory password analysis](https://improsec.com/en/active-directory-password-analysis).

`Footnote: I often find high privileged accounts with simple or non-unique passwords. When I report this to IT, they already knew the accounts had bad passwords *smh*. I don't want to do that; I would like complex tasks. Just fix the passwords.`


## Practice 3 - Reduce lateral movement and eliminate domain privilege escalation
When an AD account logs on to a system, the account's credentials are cached on the system.
Potentially it is present in multiple caches. Some caches clear upon log out, others upon reboot, others longer.
All local users of a system obviously also have their passwords persistently cached/stored on the system.
If an attacker compromises the system, the attacker can read/dump the credentials from the cache (assuming they have administrative privileges).

If an AD user's credentials are compromised, the attacker can jump to other systems accessible to that user.
If a local user's credentials are compromised, the attacker can log on to any other system where another local user has the same password.

**Reduce lateral movement - Local administrator strategy**
Systems in scope are both generic servers and workstations.
A system's local Administrators group can contain both AD accounts and local users.

There is not a silver bullet for this. In general you should have a strategy that ensures that:
1. Passwords of every local user is unique, and not used for any accounts elsewhere.
2. Users who need local administrator rights have it on as few systems as possible.

To solve point one, deploy LAPS to all AD joined systems:
* [Modern LAPS](https://www.microsoft.com/en-us/download/details.aspx?id=46899) - available only in Windows 11 Insider Preview
* [Legacy LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
A system with LAPS will set a unique password for its local administrator account and store the password in a property of the system's AD computer object. The property is readable by Domain Admins but read rights can be delegated to users/groups, **be careful to not over-delegate**.

You should configure LAPS to:
* Set a password length of minimum 12 characters.
* Change the password at minimum once per week.

To solve point two, delegate as few LAPS rights as possible. If adding AD accounts to local Administrator groups, you should control it with "shadow groups":
1. For each AD computer, create a security group "LocalAdmin_Server01".
	* Automate creation with a Scheduled Task on a DC that runs a PowerShell script as SYSTEM.
2. Add the shadow group to the computer's local Administrators group.
	* Automate it with a GPO. Add a member with name  `LocalAdmin_%ComputerName%` in policy: `Computer Configuration -> Preferences -> Local Users and Groups -> Administrators (built-in)`
3. AD users can be added as local administrators with membership of the shadow group.

The difficulty of implementing this is dependent on the environment. Nonetheless, not implementing it is a high risk.

**Eliminate domain privilege escalation - Active Directory Tiering**
The highest risk of credential dumping is if the stolen credentials are of an account that can control the entire AD domain/forest (e.g. Domain Admins). A scenario is an attacker compromising a workstation where a Domain Admin is logged on - the attacker now becomes the Domain Admin. Game over.

The simplest advice I can give is to not logon to workstations and generic servers (application, SQL, RDS) with members of highly privileged groups. Logons can be any of these:
* Logon interactively (hands on keyboard or VM console access)
* Logon with RDP
* Logon with "Run as administrator"/UAC prompt
* Run a Scheduled Task or Service

You should technically prevent this by deploying the User Rights Assignment policies:
* Deny access to this computer from the network
* Deny log on as a batch job
* Deny log on as a service
* Deny log on locally
* Deny log on through Remote Desktop Services
You must assess the impact before deploying these.

The below highly privileged groups are a good non-exhaustive starting point. They can by-design (in most cases) obtain the same rights as Domain Admins:
```
Account Operators
Administrators
Backup Operators
Cert Publishers
DnsAdmins
Domain Admins
Domain Controllers
Enterprise Admins
Enterprise Key Admins
Group Policy Creator Owners
Key Admins
Organization Management
Print Operators
Read-only Domain Controllers
Remote Management Users
Replicator
Schema Admins
Server Operators
```

PingCastle will report on the lack of the above as rule `P-LogonDenied`, but it only checks if a GPO deploys "Deny log on locally" and "Deny log on through Remote Desktop Services" for the two groups Domain Admins and Administrators; this is one of many cases where PingCastle has blind spots/false negatives.

By completing this step you have taken the first steps into implementing Tier 0 of [AD Tiering](https://learn.microsoft.com/en-us/microsoft-identity-manager/pam/tier-model-for-partitioning-administrative-privileges), in which highly privileged accounts (Tier 0 accounts) are prevented of logging in to generic servers (Tier 1 systems) and workstations (Tier 2 systems), and thereby prevented in being compromised via credential dumping.

If needed, Improsec can assist in [implementing Microsoft Active Directory Tiering](https://improsec.com/en/microsoft-active-directory-tiering); for example by implementing only Tier 0, or a complete AD forest tiering (Tier 0 + 1 + 2), or assessing the security of an existing AD tiering implementation.

`Footnote: The lack of tiering is often the reason for complete AD compromise. Fully implementing AD Tiering is a huge and complex task and should be assisted by professionals. I want to assist in that, I like complex tasks. Don't implement tiering by yourself.`

## Resources
Got suggestions to this post? Feel free to reach out on [@martinsohndk](https://twitter.com/martinsohndk).

This post is a collection of advice, mainly from my memory, which is partly based on the following:
* https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory
* https://www.cert.ssi.gouv.fr/uploads/guide-ad.html
* https://adsecurity.org/
* https://pingcastle.com/PingCastleFiles/ad_hc_rules_list.html
* https://www.purple-knight.com/security-indicators/
* Active Directory: Designing, Deploying, and Running Active Directory, 5th edition
* Windows Internals, 7th edition
* Various lists of "Hacking Active Directory" tips:
	* https://zer1t0.gitlab.io/posts/attacking_ad/
	* https://book.hacktricks.xyz/windows-hardening/active-directory-methodology