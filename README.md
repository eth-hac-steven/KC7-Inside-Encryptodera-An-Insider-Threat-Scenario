KC7-Inside Encryptodera: An Insider Threat Scenario

About This Investigation
Encryptodera is a hot new financial company specializing in fancy finance tech, like cryptocurrency, blockchain, and payment gateways. 💰

Despite healthy profit margins, Encryptodera leaders are looking to cut costs by laying off some of their workers. 😭 While nobody is happy about this, some employees are especially upset and have decided to cause some trouble.

In this module, you'll help Encryptodera get to the bottom of a dangerous disgruntled employee 😡, a rambunctious ransomware attack 🤑, and some shady dealings 🥷 happening right under their nose.




Welcome to Encryptodera!

Encryptodera Financial Solutions is a financial services company that provides payment gateways, digital wallets, and blockchain solutions.


logo

Given the recent economic downturn, rumors about upcoming layoffs at Encryptodera have understandably made employees nervous. Days after the layoff rumors started, confidential documents were leaked to the media. Encryptodera has hired you as an incident responder to investigate what happened.

Enter ready to get started.

ready
done


Now that we have access to the data, we'll need to get a lay of the land. Let's get some more information about Encryptodera.

3 How many employees work at Encryptodera?
````
Employees
| count 
````
ans : 600


4 Which employee does the IP address 10.10.0.216 belong to?
```
Employees 
| where ip_addr == "10.10.0.216"
```
ans Nakia Acosta

We can learn more about Nakia Acosta using information from other tables. Let's take her email address from the Employees table and use it in a query for the Email table.

5 How many emails did Nakia Acosta receive?
````
Email
| where recipient == "nakia_acosta@encryptoderafinancial.com"
```` 

 Ans 38

How many distinct senders were seen in the email logs from bitbingersbanking.net?

```
Email
| where sender has "bitbingersbanking.net"
| distinct sender
```

Ans 1204 

How many distinct websites did Timothy Geffre visit?

```
Employees
| where name  == "Timothy Geffre"
```
OutboundNetworkEvents
| where src_ip == "10.10.1.73"
| distinct url

ans 92

How many domains in the PassiveDns records contain the word “money”?
```
PassiveDns
| where domains contains "money"
```

ans 15

What IP did the domain moneyppl.com resolve to?

PassiveDns
| where domain == "moneyppl.com"
| distinct ip 

Ans : 211.152.115.93


How many unique URLs were browsed by employees with the name Karen?

let the_karens =
Employees 
| where name contains "karen"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (the_karens)
| distinct url
 

ans 321 

How many authentication attempts did we see to the accounts of employees with the name Karen?


let the_karens =
Employees 
| where name contains "karen"
| distinct username;
AuthenticationEvents
| where username  in (the_karens)

420

Now, we're getting started with the investigation!

A few employees have reported that Barry Shmelly has been behaving strangely. One employee showed you this tweet from Barry.



Normally Barry is a very cool, calm, and collected cat. But lately, here's been more of a snapping tiger. It might have something to do with the layoff rumors.

What is Barry's role at the company?

Employees
| where name contains "Barry Shmelly"

StackOverflow Copy Paster

You received an anymous tip from someone (who probably isn't a fan of Barry) that Barry has been slacking off at work. According to the tip, Barry sent the same "interesting" email to three other employees on January 16th.

Let's find those emails.

What is Barry's email address?

barry_shmelly@encryptoderafinancial.com

What was the subject of the interesting email (the one on January 16th) that Barry sent?


Email
| where sender == "barry_shmelly@encryptoderafinancial.com"

Ans I'm not coming in today. I'm sick of this place. We're all getting laid off anyway.


It looks like the employees who received that email all had the same role.

What was the role of the employees that received Barry's email?

```
Employees
| where email_addr  == "christopher_naylor@encryptoderafinancial.com"
```
Ans :Social Media Manager



On January 18, Barry sent an email with the subject "YOU ARE A GREEDY PIG!!!! WHAT IS WRONG WITH YOU?????"

What was the role of the recipient of that email?

 Chief Executive Officer

```
Email
| where subject contains "YOU ARE A GREEDY PIG!!!! WHAT IS WRONG WITH YOU?????"

```



Barry's behavior and emails show that he is very unhappy. Let's investigate his activity.

What's Barry's IP address? (Paste the full IP address )

Ans : 10.10.0.1


Let's keep investigating Barry's activity.

What was the complete URL that Barry was browsing on his computer regarding Cybersecurity Insiders on the afternoon of December 26th?(Paste the full url)
```
OutboundNetworkEvents
| where src_ip == "10.10.0.1"
```

https://www.cybersecurity-insiders.com/safe-ways-to-transfer-sensitive-files

It seems like Barry is really interested in finding ways to transfer sensitive files. Interesting.

Let’s continue to look at Barry's browsing history. Looks like he's researching tools he might use to move sensitive data around.

What website did he visit first on January 15th? (Paste the full URL)

https://www.7-zip.org/a/7z2002-x64.exe

7Zip isn't the only tool Barry is researching to download sensitive files. It seems Barry is also curious about USB Flash drives.

Could you provide the full URL for the website Barry searched for USB Flash Drives?

https://www.wikihow.com/Use-a-USB-Flash-Drive


Tsk tsk, Barry is a very naughty employee. It looks like he has been downloading super sensitive files from Encryptodera for "safekeeping."

That's suspicious, that's weird.

First he went after information on Encryptodera to help give him an inside advantage on his stock trades later on.

What "secret" document on business transactions did Barry download?
```
FileCreationEvents
| where hostname  == "IGOY-DESKTOP"
```
ans SECRET_MergersAndAcquisitions_Strategy2025.docx

Barry was still seething, Barry was still mad.

Barry wanted to know how much money those greedy executives had.

What document (docx) did Barry download about salaries?

ExecutiveSalaryNegotiations.docx

Barry was on a roll. Barry had some rhythm.

Barry decided he needed the secrets behind Encrytodera's algorithms.

What document (zip) did Barry download to get this?

 Encryptodera_Proprietary_Algorithms.zip



Barry's in his groove, making these files move.

Do you know the password he used to zip the files?

```
ProcessEvents
| where hostname == "IGOY-DESKTOP"
```
 securepass123

Barry was in the cloud, Barry flying high. It was not enough, Barry went and got his drive.

Barry stored a few extra sensitive files on his flash drive.

What is the name of the drive on which Barry stored the final files?

SchmellyDrive


Downloading confidential files, anomalous login times, and changes in behavior are indicative of an insider threat. From what we've discovered, Barry fits that profile.

Although it's too late to stop him, it's a good thing we were able to detect this activity so we can take appropriate measures.

Type gotheem to take credit

Some employees have said that they can't use their computers. One employee mentioned that they saw this suspicious file show up on their system.

img of ransomnote

What is the filename of this note?
```
FileCreationEvents
| where hostname  == "IGOY-DESKTOP"
```
 or look at the ransom note you should see the name.

ans : YOU_GOT_CRYTOED_SO_GIMME_CRYPTO.txt


The file asks for payment and says all the files have been encrypted.

What kind of attack is this?

ransomware

Ransomware can be very impactful and disruptive to businesses. We'll want to investigate this as quickly as possible and understand what happened.

On how many machines was this .txt file seen?

```
FileCreationEvents 
| where filename  == "YOU_GOT_CRYTOED_SO_GIMME_CRYPTO.txt" 
| distinct hostname
```

Ans : 306


Wow, that's a lot of machines! Let's pick one to focus on first. It might make sense to focus on the very first victim machine.

What time was  the ransomnote first seen?

Ans  : 2024-02-17 02:34:54

We'll begin our investigation by looking at the earliest machine to have been encrypted.

What is the hostname of the system where the ransom note was first seen?

UL8R-MACHINE


Look closer at UL8R-MACHINE around the time when the ransom note was seen (2024-02-17).

How many files were encrypted on this machine?
```
FileCreationEvents
| where hostname == "UL8R-MACHINE"
| where filename contains "umadbro"
```
ans 50

What is the extension that was used on the encrypted files?

umadbro



Well, those files can't have encrypted themselves. Let's look at the ProcessEvents logs to see if we can find any traces of that file extension on UL8R-MACHINE.

ProcessEvents
| where hostname == "UL8R-MACHINE"
| where process_commandline has "umadbro"

What command was run that references the ransomware extension?

Ans: start /b C:\\ProgramData\\files_go_byebye.exe -encrypt -target C:\\Users\\ -ext .umadbro

That command mentions an executable file called files_go_byebye.exe. Now, we need to find how that file got on this machine.

When did files_go_byebye.exe appear on this machine?

```
FileCreationEvents
| where hostname == "UL8R-MACHINE"
| where filename contains "files_go_byebye"
```

 2024-02-17T02:30:50Z


Now, let's look for suspicious activity that happened around that time on this host.

You can use this query to conduct temporal analysis on this host, where we look for activity based on timestamps.
```
ProcessEvents
| where hostname == "UL8R-MACHINE"
| where timestamp between (datetime("2024-02-16") .. datetime("2024-02-18"))
```
How many commands were run on UL8R-MACHINE during this timeframe?

ans: 23

There's a base64 encoded powershell command run in this time window.

What domain does the encoded PowerShell reference?

encoded image 

decrypt using cyber chef

 notification-finance-services.com

Right before the base64-encoded PowerShell is run, another strange command runs.

What command is run right before the base64-encoded PowerShell?

Right before the base64-encoded PowerShell is run, another strange command runs.

What command is run right before the base64-encoded PowerShell?

 gpupdate /force


gpupdate /force give us a clue that the attacker might have compromised the domain controller to deploy this ransomware.

This command forces an update of Group Policy Objects (GPOs), which are tools used legitimately to control settings in a network. An attacker with elevated permissions can create a malicious GPO to deploy malware to a large number of devices.

How many devices ran the gpupdate /force command?


ProcessEvents
| where process_commandline contains "gpupdate /force"
| distinct hostname

 306

Before they can compromise the domain controller, the attackers must first find its location on the network. They will use Discovery techniques in order to learn more about the environment they're attacking. Attackers will often run Discovery commands when they first compromise a new machine.

One common discovery command is systeminfo, which gives an attacker information about the device they've compromised.

How many machines at Encryptodera ran "systeminfo"?

8


What was the timestamp for the first time the command was run?

2024-02-02 03:32:36

How many days elapsed between when the attackers ran discovery commands and when the ransomware attack started?

 15

Wow, the threat actor was in the network for over two weeks before they started deploying ransomware!

Let's find out what else they did during that time.

What is the hostname of the device on which the attackers first ran systeminfo?

 41QI-LAPTOP


Let's look closer at 41QI-LAPTOP to see what else happened.

Shortly after running systeminfo, the actor used nltest /dclist to identify the company's domain controller. The domain controller is responsible for controlling authentication of users and computers in a network. The domain controller can be a valuable target for malicious actors because it can give them access to many devices and accounts in the network.

We also already know that the actor likely compromised the domain controller to push the malicious GPO.

What was the full commandline used by the threat actor when running nltest /dclist? (paste the full commandline)

ans : cmd.exe /C nltest /dclist:encryptoderafinancial.com


Your investigative partner mentions to you that they found a suspicious file on another system they were investigating. The file had a double extension- .xlsx.exe

A malicious actor might use double file extensions, like ".xlsx.exe", to trick a user into thinking they're opening a safe file, like an Excel document, when it's actually a harmful program. This technique works because some computers hide the last part of the file name, making the dangerous ".exe" part invisible.

What is the full name of the .xlsx.exe file on 41QI-LAPTOP?

FileCreationEvents
| where  hostname == "41QI-LAPTOP"
| where filename contains "xlsx.exe"

Ans : Company_Financials_Q1_2024_Review.xlsx.exe


What file shows up a few seconds after the .xlsx.exe file?

FileCreationEvents
| where  hostname == "41QI-LAPTOP"


 screenconnect_client.exe

ScreenConnect is a legitimate remote access tool. Some threat actors use remote access tools, like ScreenConnect, to establish persistence and gain remote access to a network.

How many devices does screenconnect_client.exe appear on?

3


It looks like the threat actor is using double-extension files to deploy ScreenConnect on a few different devices.

Let's go back to Company_Financials_Q1_2024_Review.xlsx.exe and see if we can figure out how it was delivered to the victim.

Check the Email logs to see if the .xlsx.exe file was sent in a link. What email address was used to send this file?
```
Email
| where link contains "xlsx.exe"
```
 ans : barry_shmelly@encryptoderafinancial.com


Wait a second, that's the disgruntled employee we investigated earlier! Hmm.. that's strange. Let's take a closer look at all of Barry's emails.

Starting on 2024-02-01, it looks like Barry's account is used to send unusual emails.

How many unusual emails were sent by Barry?

9


Taking good notes is an important part of investigating cyber intrusions. You may need to refer back to the users who received unusual emails from Barry later. Copy the recipients' email addresses and paste them somewhere safe. You can use a notepad, or add them in a comment in ADX!

To add a comment, you can add // to the start of the line, or highlight several lines and press CTRL+/ on your keyboard!

Type got it once you've made a note of these recipients.

got it 


According to his emails, Barry quit Encryptodera on January 18th. How could he have sent these emails on February 1st? Maybe an unauthorized party gained access to Barry's account and used it to send these emails.

Let's look at Barry's AuthenticationEvents to check for anything unusual.

What IP was used to sign into Barry's account on February 1st?

AuthenticationEvents
| where username == "bashmelly"

Ans 143.38.175.105

How many other accounts did that IP log into?

 0;none

143.38.175.105 is an external IP address. Since the attacker didn't log in to any other accounts externally, maybe they moved around within the network once they got inside. This is called lateral movement.

Let's see if we can find evidence of the threat actor moving laterally within the network.

We learned earlier that, after compromising a device, the attackers conduct discovery by running systeminfo and some other commands.

Let's take all the hosts where the threat actor ran systeminfo and look for common login patterns across those devices. You'll need to use a let statement so you can easily query data from all of these devices at once. Here's a template to help you with this:

let hosts = ProcessEvents
| where process_commandline has "systeminfo"
| distinct hostname;
AuthenticationEvents
| where hostname in (hosts)
| summarize dcount(hostname) by src_ip
| order by dcount_hostname desc


This tells us how many different devices each IP logged into.

How many IPs logged in to all 8 devices where the attacker ran systeminfo?

2

There are two IPs that logged in to all 8 devices where the threat actor conducted system discovery. Both of these IPs are private IPs, that means they are internal to the network. That's a good indication that the attacker likely moved laterally within the network.

Let's just focus on one of those IPs 10.10.0.138

What is the role of the employee who this IP address belongs to?

 System Administrator


How many successful logins were made from this IP?

```
AuthenticationEvents
| where src_ip == "10.10.0.138"
| where result == "Successful Login"
```

 554


One of the hosts logged into from this IP is especially concerning. This host is a server (and it's not the mail server)!

What is the hostname of the server the attackers logged into?

 DOMAIN_CONTROLLER_SERVER


Wipe away your tears. It's time to figure out how the threat actor compromised the domain controller.

What username was used to log into the DOMAIN_CONTROLLER_SERVER?

lihenry_domain_admin


It looks like the threat actor stole domain admin credentials, and used them to log into the domain controller! 😱

The threat actor must have stolen these credentials from somewhere else in the network.

What laptop did the lihenry_domain_admin account sign into? (Enter the hostname)

AuthenticationEvents
| where username == "lihenry_domain_admin"

 GJ95-LAPTOP

Let's check to see if the threat actor ran mimikatz on GJ95-LAPTOP.

Did the threat actor run mimikatz on this device? If so, enter the command line the attacker ran. If not, enter no.

ProcessEvents
| where hostname == "GJ95-LAPTOP"
| where process_commandline contains "mimikatz"

Ans: totally_not_mimikatz.exe "sekurlsa::logonpasswords"

That's not great. The attackers dumped credentials on this device.

Who does this device belong to? (Enter the employee's name)

 Valerie Orozco


Let's see if we can find evidence of the threat actor stealing the domain admin credentials from GJ95-LAPTOP.

Mimikatz is a popular credential dumping tool used by malicious actors.

What is the MITRE ATT&CK ID for mimikatz?

S0002


Remember when we said good notes are important? Go back and check those notes now!

Was Valerie Orozco targeted in the phishing emails sent from Barry Shmelly?

Email
| where sender  == "barry_shmelly@encryptoderafinancial.com"

 yes

What is the name of the file that was sent to Valerie in the phishing email?

 Employee_Contact_List_Updated_March_2024.docx.exe

Did Valerie click the link? If so, enter the timestamp when she clicked the link. If not, enter 'no'

```
OutboundNetworkEvents
| where src_ip == "10.10.0.18"
| where url contains "Employee_Contact_List_Updated_March_2024.docx.exe"
```
 no

Hmm.. so the threat actor didn't successfully phish Valerie. But we know the actor dumped credentials on her machine.

Now we have to find out how the actor got onto Valerie's machine.

How many different user accounts logged into Valerie's machine?


AuthenticationEvents
| where hostname  == "GJ95-LAPTOP"
| distinct username

 3

Of the three accounts that logged into Valerie's account, we've already seen two: vaorozco (Valerie's account) and (lihenry_domain_admin), the account the threat actor stole from Valerie's machine.

The third account, systadmi_local_admin, is new! Let's look closer at that one.

How many unique hosts did this user account attempt to log into?

```
AuthenticationEvents
| where username == "systadmi_local_admin"
| distinct hostname
```

 10

It looks like the account systadmi_local_admin was compromised. Let's find out how those credentials were stolen!

Run the query below… It's a little more complicated than you're used to. That's okay! Sometimes analysts don't write queries themselves, but they instead use queries someone else wrote for them!

```
let hosts = FileCreationEvents
| where filename has "screenconnect"
| distinct hostname;
AuthenticationEvents
| where hostname in (hosts)
| where username has "systadmi"
| where result has "Successful"
| join (
    Employees 
    | project ip_addr,role,email_addr,name
) on $left.src_ip==$right.ip_addr
| project SourceIpName=name, a="who is a", SourceIpUserRole=role, b="logged onto",hostname, c="using", username, d="at",timestamp
```

The systadmi_local_admin account should only be used to log in to devices that belong to IT-related users.

Which user NOT in an IT role was improperly using the systadmi_local_admin credentials? (This is likely a sign of compromise)

 Ans : Robin Kirby

When was Robin phished by Barry Shmelly's account?

 2024-02-01T03:59:30Z

So Robin WAS phished by Barry Shmelly's account!

Let's recap. A threat actor 😈 compromised Barry Shmelly's account and logged into it from 143.38.175.105. Once the actor gained access to Barry's account, they used it to target 9 employees in a phishing 🎣 attack.

One of the users compromised by this phish was Robin Kirby. The threat actor used stolen local admin credentials 🔑 to move laterally and login from Robin Kirby's machine to Valerie Orozco's machine!

Once they accessed Valerie's machine, they dumped the domain admin credentials, then logged in to the domain controller 👑. They used their access to the domain controller to deploy ransomware to 306 machines at Encryptodera.

Congrats! You solved the mystery of the ransomware attack! 👏

Before we leave, let's see if there's any other funny business happening around here…

Type letsgo to move on!




⚠️ This section is a little bit more of a challenge. You got this! 💪

Encrytodera has decided to switch from Email to Tiktok as their primary work communication platform. That's right, all communications in the future of Encryptodera will be recorded in 12 second videos - complete with fun dances 💃🏻.

In order to make sure there is enough bandwidth for this transition, the network administrator was tasked to do some research to see how much more traffic the network could handle without failing (tiktoks take a lot of bandwith you know!).

During this debugging process, he noticed an unusually large amount of data being sent to one IP address on February 5th

Which IP address received the largest amount of data on Feb 5th?

NetworkFlow
| where timestamp between (datetime("2024-02-5") .. datetime("2024-02-6"))

182.56.23.121


Perhaps if we eliminated this data flow, we could get the network to perform better. This would allow all the tiktoks to flow much faster!

First, we should make sure the traffic to that IP isn't business critical.

When was data first sent to this IP? (paste the full timestamp)

 2024-01-21T13:28:33Z

NetworkFlow
| where src_ip == "10.10.0.2"
| where dest_ip == "182.56.23.121"
| distinct timestamp

Wow so we've been sending data to this IP for a few weeks now.

On how many distinct days have we sent data to this IP?

 27

That amount of data being sent is definitely sus.

What service is used for the port to which this data is being transferred?

 FTP;

What is the total amount of data transferred to this IP address?

 nothing yet 

It's possible that this could be a common or legitimate service. Let's attempt to validate this hypothesis.

How many distinct employees have sent data to this IP address?

 1

Ok that's a major clue!

Whose name is linked to that IP address? Provide the employee's name.

 Jane Smith

Oooh tea! We know the employees name.

What is that employee's role?

Ans : Cryto Bruh (Blockchain Contractor)

What is the total amount of data transferred to this IP address?

 208138

```
NetworkFlow
| where dest_ip == "182.56.23.121"
| summarize TotalBytes = sum(bytes)
```


InboundNetworkEvents
| where src_ip == "10.10.0.2"
| project timestamp, method, url
| order by timestamp asc


A 'Crypto Bruh' is a new role that Encryptodera created to engage with community members across various platforms, including social media, forums, and other online channels. It's a bit unusual for a Crypto Bruh to be sending out this much data.

Management has decided it would be prudent to initiate some insider threat monitoring on Jane.

Let's look for any suspicious browsing activity from Jane to Encryptodera's website. Hmmm… Jane is mighty nosy!

We see her looking for the location of the company's __ __ __ __ (4 words)

cold storage crypto wallets





Ok something is amiss. Something is afoot!
Let's check Jane's emails to see how she plans to steal the loot!

Who was Jane having a suspicious conversation with? (email address)

 elboss@westealurcrypto.com

What a plan they've hatched! And they almost got away with it.

What IP address did the boss man provide to help with smuggling the data?

Email
| where sender contains "elboss@westealurcrypto.com"

 182.56.23.121

Jane has a plan, oh so grand, to steal all the crypto in the land.
But she can't quite do it with an empty hand.

What is the name of the data exfil tool Jane downloads to help with her operation?

ftp_client.exe


What is the name of the crypto theft tool Jane downloads to help with her operation?

 crypto_stealer.exe

ProcessEvents
| where hostname == "GOTI-LAPTOP"
| where process_name contains "crypto"

Now that Jane has the tool, she has us looking like fools.

Jane executes a command to stage the data she will steal.

To what path does Jane point her data exfiltration tool?

 C:\\Users\\jasmith\\ToTheMoon\\;tothemoon


In her final act, Jane sends all the secrets out the door.

At what tempo does she set the tool to run? (one word)

 daily



What password does Jane use for the tool?

Ugot2muchCRYTOw3llt4k3it0FFurH4ND5

ProcessEvents
| where hostname == "GOTI-LAPTOP"
| where parent_process_name contains "cmd"



user of interest
```
{
  "hire_date": "2020-12-29 00:00:00+00:00",
  "name": "Nakia Acosta",
  "user_agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:50.0) Gecko/20100101 Firefox/50.0",
  "ip_addr": "10.10.0.216",
  "email_addr": "nakia_acosta@encryptoderafinancial.com",
  "company_domain": "encryptoderafinancial.com",
  "username": "naacosta",
  "role": "IT Helpdesk Technician",
  "hostname": "P224-LAPTOP"
}
```
```
{
  "hire_date": "2020-12-28 00:00:00+00:00",
  "name": "Timothy Geffre",
  "user_agent": "Mozilla/5.0 (Windows NT 6.3; rv:46.0) Gecko/20100101 Firefox/46.0",
  "ip_addr": "10.10.1.73",
  "email_addr": "timothy_geffre@encryptoderafinancial.com",
  "company_domain": "encryptoderafinancial.com",
  "username": "tigeffre",
  "role": "Sales Representative",
  "hostname": "U113-LAPTOP"
}
```
```
{
  "hire_date": "2021-01-01 00:00:00+00:00",
  "name": "Barry Shmelly",
  "user_agent": "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)",
  "ip_addr": "10.10.0.1",
  "email_addr": "barry_shmelly@encryptoderafinancial.com",
  "company_domain": "encryptoderafinancial.com",
  "username": "bashmelly",
  "role": "StackOverflow Copy Paster",
  "hostname": "IGOY-DESKTOP"
}
```
```
{
  "hire_date": "2024-01-05 00:00:00+00:00",
  "name": "Jane Smith",
  "user_agent": "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.117 Safari/537.36",
  "ip_addr": "10.10.0.2",
  "email_addr": "jane_smith@encryptoderafinancial.com",
  "company_domain": "encryptoderafinancial.com",
  "username": "jasmith",
  "role": "Cryto Bruh (Blockchain Contractor)",
  "hostname": "GOTI-LAPTOP"
}
```

"nancy_owens@encryptoderafinancial.com"
eulah_foster@encryptoderafinancial.com
robin_kirby@encryptoderafinancial.com
valerie_orozco@encryptoderafinancial.com
