# KC7 Inside Encryptodera: An Insider Threat Scenario

## About This Investigation

Encryptodera is a financial services company specializing in cryptocurrency, blockchain, payment gateways, and digital wallets. Rumors of layoffs caused significant tension among employees, but the situation escalated into a much larger cyber incident involving:

- A disgruntled insider
- Ransomware deployment across the network
- A phishing and lateral-movement chain
- A second insider attempting to exfiltrate cryptocurrency data

![Encryptodera](images/Encryptopedra%20img.png)

## Welcome to Encryptodera

After confidential documents were leaked to the media, Encryptodera hired an incident responder to investigate the activity. This README documents the investigation findings and the supporting screenshots captured while reviewing the logs.

---

# Investigation 1: Environment and Employee Baseline

### How many employees work at Encryptodera?

**Answer: 600**

![Employee count](images/Employee%20count.png)

### Which employee owns IP `10.10.0.216`?

**Answer: Nakia Acosta**

![Owner of 10.10.0.216](images/owner%20of%20the%20ip%2010.10.0.216.png)

Nakia Acosta's details:

- **Email:** nakia_acosta@encryptoderafinancial.com
- **Role:** IT Helpdesk Technician
- **Username:** naacosta
- **Hostname:** P224-LAPTOP

She received **38 emails**.

![Emails received by Nakia Acosta](images/emails%20recieved%20by%20Acosta.png)

### Distinct senders from `bitbingersbanking.net`

**Answer: 1204**

![Distinct senders](images/distinct%20sender%20from%20bitbingersbanking.net.png)

### Distinct websites visited by Timothy Geffre

**Answer: 92**

![Sites visited by Timothy](images/sites%20visited%20by%20timothy.png)

### Passive DNS results containing "money"

**Domains found:** 15

**`moneyppl.com` resolved to:** `211.152.115.93`

![Domains containing money](images/how%20many%20domains%20have%20money%20in%20thier%20names.png)

![moneyppl.com IP](images/ip%20for%20the%20domain%20moneyppl.png)

### Employees named Karen

- **Distinct URLs visited:** 321
- **Authentication attempts:** 420

![Karen authentication attempts](images/auth%20attempts%20made%20by%20karens.png)

---

# Investigation 2: Barry Shmelly — Disgruntled Employee

## Employee Profile

- **Name:** Barry Shmelly
- **Role:** StackOverflow Copy Paster
- **Email:** barry_shmelly@encryptoderafinancial.com
- **IP:** `10.10.0.1`
- **Hostname:** IGOY-DESKTOP
- **Username:** bashmelly

![Barry Shmelly's role](images/Barry%20shmelly%20%20role.png)

## Barry's Email Activity

Barry sent a January 16 email with the subject:

> I'm not coming in today. I'm sick of this place. We're all getting laid off anyway.

![Barry email subject](images/subject%20%20of%20the%20mail%20sent%20by%20barry.png)

The recipients of Barry's January 16 email were **Social Media Managers**.

Barry also sent an email on January 18 with the subject:

> YOU ARE A GREEDY PIG!!!! WHAT IS WRONG WITH YOU?????

The recipient was the **Chief Executive Officer**.

![Email recipient](images/recipient%20of%20the%20question.png)

![Recipient role](images/role%20%20of%20the%20recipient.png)

## Suspicious Web Activity

On December 26, Barry browsed:

**https://www.cybersecurity-insiders.com/safe-ways-to-transfer-sensitive-files**

![Barry's cybersecurity search](images/what%20barry%20search%20on%20Dec%2026.png)

Barry's first recorded download-related search on January 15 was:

**https://www.7-zip.org/a/7z2002-x64.exe**

![Barry's January 15 search](images/barry%20search%20on%2015-jan.png)

He also searched for instructions on USB flash drives:

**https://www.wikihow.com/Use-a-USB-Flash-Drive**

![USB flash-drive search](images/usb%20web%20search%20made%20by%20barry.png)

## Confidential Downloads

| Item | Filename |
|---|---|
| Mergers and acquisitions strategy | `SECRET_MergersAndAcquisitions_Strategy2025.docx` |
| Executive salaries | `ExecutiveSalaryNegotiations.docx` |
| Proprietary algorithms | `Encryptodera_Proprietary_Algorithms.zip` |
| Archive password | `securepass123` |
| Flash drive | `SchmellyDrive` |

![Secret business document](images/Secret%20file%20downloaded%20by%20barry.png)

![Salary document](images/Salary%20%20file%20downloaded%20by%20barry.png)

![Algorithm file](images/Algorithm%20file%20downloaded%20by%20barry.png)

![Zip password](images/passwd%20used%20to%20zip%20files.png)

![Barry's flash drive](images/the%20name%20of%20barrydrive.png)

These downloads, anomalous behavior, and unusual login times indicated an insider-threat pattern.

---

# Investigation 3: Ransomware Incident

## Ransom Note

The ransom note was named:

**`YOU_GOT_CRYTOED_SO_GIMME_CRYPTO.txt`**

![Ransom note](images/Ransomnote.png)

![Ransom note filename](images/name%20of%20the%20ransomnote.png)

The incident was **ransomware**, and the note appeared on **306 distinct machines**.

The first victim was:

- **Hostname:** UL8R-MACHINE
- **First seen:** `2024-02-17 02:34:54`

![First ransom-note timestamp](images/time%20the%20ransom%20note%20was%20seen%20first.png)

## UL8R-MACHINE Analysis

- **Encrypted files:** 50
- **Encryption extension:** `.umadbro`
- **Malicious executable:** `files_go_byebye.exe`
- **Executable creation:** `2024-02-17T02:30:50Z`
- **Commands observed in the investigation window:** 23

The encryption command was:

```text
start /b C:\ProgramData\files_go_byebye.exe -encrypt -target C:\Users\ -ext .umadbro
```

![Encryption command](images/command%20that%20started%20the%20encryption.png)

The executable appeared before the ransom note:

![Malicious executable creation](images/first%20%20time%20mal%20exe%20appear%20on%20the%20sys.png)

## Encoded PowerShell

An encoded PowerShell command referenced:

**`notification-finance-services.com`**

Immediately before the encoded PowerShell command, the attacker ran:

```text
gpupdate /force
```

![Encoded PowerShell domain](images/base64%20domain.png)

![PowerShell decoder](images/dcode%20the%20encode.png)

![Strange command](images/strange%20command.png)

The `gpupdate /force` command ran on **306 hosts**.

## Discovery and Initial Access

- Machines that ran `systeminfo`: **8**
- First `systeminfo` timestamp: `2024-02-02 03:32:36`
- Elapsed time before ransomware: **15 days**
- First host: **41QI-LAPTOP**

![First systeminfo host](images/hostname%20of%20the%20sys%20that%20ran%20sysinfo%20first.png)

The threat actor identified the domain with:

```text
cmd.exe /C nltest /dclist:encryptoderafinancial.com
```

![Domain controller discovery](images/DC%20identifier%20command.png)

## Double-Extension and Remote Access Delivery

The malicious file on 41QI-LAPTOP was:

**`Company_Financials_Q1_2024_Review.xlsx.exe`**

The file appearing shortly afterward was:

**`screenconnect_client.exe`**

ScreenConnect appeared on **3 devices**.

![Double-extension file](images/double%20exetension.png)

![ScreenConnect payload](images/exe%20after%20%20the%20double%20ext%20file.png)

The compromised address used to send the malicious link was Barry's account:

**barry_shmelly@encryptoderafinancial.com**

![Barry's compromised mail account](images/comprised%20mail%20send%20the%20doubke%20exetension%20file.png)

## Barry Account Compromise

Starting February 1, Barry's account sent **9 unusual emails**.

The external IP that signed into Barry's account was:

**`143.38.175.105`**

It was not used to log into any other account.

![External login from 143.38.175.105](images/successful%20rdp%20login%20by%20143.png)

The IP `10.10.0.138` logged into all discovery hosts and was assigned to a **System Administrator**.

- Successful logins from `10.10.0.138`: **554**
- Server later accessed: **DOMAIN_CONTROLLER_SERVER**
- Domain-admin username: `lihenry_domain_admin`

![Successful administrator logins](images/successful%20login%20made%20by%20%20the%20sys%20admin.png)

![Attacker login to domain controller](images/attacker%20login%20to%20the%20DC.png)

## Credential Theft on GJ95-LAPTOP

The `lihenry_domain_admin` account signed into:

**GJ95-LAPTOP**

![Linenry account laptop](images/laptop%20lihenry_domain_admin%20logged%20on%20to.png)

The machine belonged to **Valerie Orozco**. The attacker ran:

```text
totally_not_mimikatz.exe "sekurlsa::logonpasswords"
```

The MITRE ATT&CK tool identifier was:

**S0002**

Valerie was included in the phishing campaign, and the attached filename was:

**`Employee_Contact_List_Updated_March_2024.docx.exe`**

No evidence showed that Valerie clicked the link.

![Valerie phishing email](images/phishing-email%20sent%20to%20%20valerie.png)

### User accounts on GJ95-LAPTOP

The machine had three distinct accounts:

- `vaorozco`
- `lihenry_domain_admin`
- `systadmi_local_admin`

The `systadmi_local_admin` account attempted to log into **10 hosts**.

![Systadmi login attempts](images/attempted%20log%20in%20by%20systadmi.png)

The non-IT employee improperly using local-admin credentials was:

**Robin Kirby**

Robin was phished at:

**2024-02-01T03:59:30Z**

![Robin phishing timestamp](images/when%20barry%20phish%20robin.png)

## Ransomware Attack Chain

1. Barry's account was compromised externally.
2. Nine phishing emails were sent to employees.
3. Robin Kirby was compromised.
4. Stolen local-admin credentials moved laterally to GJ95-LAPTOP.
5. Mimikatz dumped domain-admin credentials.
6. The attacker logged into the domain controller.
7. A malicious GPO deployed ransomware to 306 machines.

---

# Investigation 4: Jane Smith — Data Exfiltration

## Jane's Profile

- **Name:** Jane Smith
- **Role:** Cryto Bruh (Blockchain Contractor)
- **IP:** `10.10.0.2`
- **Hostname:** GOTI-LAPTOP
- **Username:** jasmith

## Suspicious Network Transfer

The largest amount of data sent on February 5 went to:

**`182.56.23.121`**

![Bytes sent on February 5](images/bytes%20sent%20on%20the%205th.png)

The first transfer occurred at:

**2024-01-21T13:28:33Z**

The destination had been contacted for:

- **Distinct days:** 27
- **Distinct employees:** 1
- **Service:** FTP
- **Total bytes transferred:** 208138

![Malicious FTP IP](images/mal%20ftp%20ip.png)

## Jane's Suspicious Browsing

Jane browsed Encryptodera's internal documentation and searched for:

**"cold storage crypto wallets"**

![Jane's search](images/what%20jane%20was%20search%20for.png)

## Jane's Suspicious Email Conversation

The external conversation partner was:

**elboss@westealurcrypto.com**

The boss provided Jane with the smuggling destination:

**`182.56.23.121`**

![Conversation with suspicious email account](images/coms%20with%20bad%20mail.png)

![Conversation with suspicious IP](images/coms%20with%20sus%20ip.png)

## Exfiltration Tools

- **FTP exfiltration tool:** `ftp_client.exe`
- **Cryptocurrency theft tool:** `crypto_stealer.exe`

![FTP exfiltration tool](images/tool%20used%20for%20ftp%20exfil.png)

![Crypto theft tool](images/crypto%20theft%20tool.png)

Jane staged data in:

```text
C:\Users\jasmith\ToTheMoon\
```

The tool was scheduled to run:

**daily**

Its password was:

**Ugot2muchCRYTOw3llt4k3it0FFurH4ND5**

![To-the-Moon staging](images/to%20the%20moon.png)

![Jane's tool password](images/the%20password%20jane%20used%20fot%20the%20tool.png)

---

## Investigation Conclusion

The Encryptodera investigation uncovered two separate insider-threat events that became connected to a broader intrusion:

1. **Barry Shmelly** downloaded sensitive files and later had his account compromised for phishing activity.
2. **The threat actor** moved laterally, stole domain credentials, deployed ransomware, and affected 306 systems.
3. **Jane Smith** exfiltrated data to an external IP using FTP and cryptocurrency theft tools.

The evidence in this repository demonstrates how multiple log sources can be correlated to identify employee abuse, phishing, credential theft, lateral movement, ransomware deployment, and data exfiltration.
