# Cloud Security Table Top Exercises
A list of table-top exercises to discuss for cloud security readiness. Most are collected from readings on the Internet, some are created from actual incidents or events, others are simply for fun.

## Sources
* Matt Fuller - https://levelup.gitconnected.com/cloud-security-table-top-exercises-629d353c268e

# Exercises

## Malicious VPC Peering Request
### Scenario: 
An attacker has discovered the VPC ID of a VPC in your AWS account via accidentally-published documentation and requested a VPC peering. One of your users assumed it was a legitimate request and accepted the peering connection, including creating routes to your backend resources per the defined process.
### Notes: 
While this attack requires several layers of defense to fail, it does raise the question of how you manage inbound VPC peering requests, which users have permission to accept them, and whether your central security team could easily create a mapping of all peered accounts to readily identify external connectivity to accounts not owned by the same organization.
## Compromised Lambda Layers
### Scenario: 
A third-party Lambda layer used by your teams has been compromised and malicious code has been injected. Because the layer is not part of your build process, your build-time security scans do not detect the malicious payloads.
### Notes: 
Lambda layers present a unique security risk. Like all code pulled from untrusted sources, it should be scanned and audited regularly.
## Injected CloudFormation Templates
### Scenario: 
S3 “READ” and “WRITE” ACLs for anonymous users were accidentally added to the S3 bucket used to store CloudFormation templates as part of your build pipelines. A malicious user has been copying these templates and injecting malicious resource types, such as cross-account admin IAM roles, into the stacks.
### Notes: 
There is a lot to unpack here — S3 bucket security, the access given to your build machines, and event-level monitoring for the resources being deployed by your CloudFormation stacks.
## Broken CloudTrail Logs
### Scenario: 
An enterprising developer saw the “PutObject by cloudtrail.amazonaws.com” policy on the S3 bucket used by CloudTrail, assumed it was a mistake, removed it, and now CloudTrail logs have been broken for 6 hours.
### Notes: 
Besides the fact that permissions on the S3 bucket used by CloudTrail should be heavily restricted, this scenario raises an important question: how do you detect when logs are missing? It’s fairly easy to configure alerts when certain events occur, but what about when no events are occurring? While it may feel trivial, these kinds of alerts are often overlooked during an initial deployment.
## A Mysterious EC2 Instance
### Scenario: 
A c5.xlarge AWS EC2 instance named “temp-do-not-delete” was discovered running in a region your developers never use. No one knows where it came from, but its CPU has been maxed at 100% for the last 4 weeks. Upon further inspection, it is discovered that the instance is mining Bitcoins.
### Notes: 
This attack has been seen repeatedly over the last several years. This scenario should raise questions around your monitoring processes (especially in unused regions), as well as inventory management and host-based security controls.
## Malware on a Public AMI
### Scenario: 
A public AMI used by several of your development teams triggers a positive result during a routine malware scan. Your teams claim that this AMI has been in use for several weeks, and worse, a variety of additional AMIs have been created based on this image.
### Notes: 
Public AMIs should always be treated as untrusted code, of course, but this problem grows exponentially when images are built based on previous images. Unfortunately, there is no easy way to view the ancestry tree of a given AMI, so tracking down the potential impact of this vulnerability will require some complex sleuthing through CloudTrail logs, potentially across multiple accounts.
## Strange Application Behavior
### Scenario: 
Your on-call security engineer is paged at 1AM on Saturday morning due to an elevated number of “s3:DeleteObject” calls within a short timeframe. After a quick investigation, the engineer determines that: 
1. the bucket does not have versioning enabled, so the delete calls are irreversible, 
2. the bucket appears to contain sensitive user data files that are part of a running application, 
3. the application interfacing with this bucket requires “DeleteObject” permission as part of its standard functionality, but that the rate of deletes has suddenly spiked from 100/hour to over 100,000/hour.
### Notes: 
Sometimes the hardest security issues to debug involve application-level anomalies. In this situation, what constitutes a “normal” rate of “DeleteObject” calls? Did the application simply receive a spike in traffic, or was there an actual security compromise? In many cases, the security engineer may need to involve additional on-call engineers from the application teams, which will complicate remediation timelines. Does your security on-call have the proper decision-making tools (and authority) to potentially break a production application if a security breach is suspected?
## Public AWS Key and Secret
### Scenario: 
An AWS access key and secret with Power User-level permissions was accidentally committed to a public Bitbucket repository. The engineer who committed the keys quickly reverted the commit and did not report the incident. However, he forgot that the keys remain in Git history. The keys are only discovered and wiped one week later during a deep search scan by your security team. There does not appear to be any suspicious activity in the affected account.
### Notes: 
Accidental exposure of keys is an incredibly common cloud security incident that is nearly guaranteed to occur with depressing regularity at large organizations. Your security team should have a clearly documented process for handling these situations. Public exposure of a privileged credential set is similar to leaving your front door unlocked while on vacation; even if you return home and nothing appears to be touched, you can never shake the feeling that someone was in your house.
## Rapidly-Escalating DDoS
### Scenario: 
A critical application API has started to receive spikes in traffic from random geographic locations. With each passing hour, the rate of traffic is growing by 100%. So far, your autoscaling groups have been able to scale your backend instances horizontally to handle the apparent DDoS and the Application Load Balancer appears unfazed, but your application team is concerned about the growing cost and potential for downtime. Your organization does not currently subscribe to AWS Shield.
### Notes: 
A DDoS attack is a concerning possibility for any team, but as these attacks grow in both size and frequency, a proper response should be planned well in advanced. All levels of the application infrastructure need to be evaluated, from DNS and load balancers to autoscaling groups and policies and monitoring. Additionally, there should be an approved set of tools, such as AWS WAF and Shield, that can be leveraged during such attacks. The middle of a DDoS attack is not an ideal time to be trying to get approval from finance for a $3,000/month service.
## Resources Shared with an Unrecognized Account ID
### Scenario: While debugging an issue with an RDS database containing sensitive customer data, an engineer discovers an automated backup from 7 days ago that has been shared with an AWS account ID she doesn’t recognize. She reports the incident to your security team, who are unable to locate this AWS account in any of the 500 accounts owned by your organization.
### Notes: 
While this incident may have been an accident — a mistyped account ID, or a new account that has yet to be recorded in your organization’s wiki — it may also represent a compromise. Even if there is no evidence of malicious intent, do you need to notify your customers of a potential data exposure? Do you have logs proving this unknown account never accessed the shared backup? Can you prove that one of your existing users or roles did not share the backup maliciously?
## Root Account Usage from Foreign Country
### Scenario: 
Your organization’s policy is to enable MFA on all root user accounts, lock the password and MFA material in an offline safe, and use IAM roles for day-to-day administration. Yet a moment ago, your security team received an alert that the root account for one of your AWS accounts was accessed from Cyprus. You have no employees in Cyprus.
### Notes: 
Time is of the essence in all of our scenarios, but perhaps none more so than this one. By the time this alert is triggered, read, and processed by your security team, it is likely that a potential attacker has already back-doored themselves into your account and potentially disabled your access. How do isolate this account from your other non-compromised accounts? Do you have the information you need readily available to initiate an account recovery with AWS? Do you know which other systems this account has access to that can be temporarily blocked?
## CSRF Vulnerability and Exposed Instance Credentials
### Scenario: 
During a routine internal pentest, your application security team discovers a CSRF vulnerability in an application running in an Autoscaling Group of EC2 instances. Your cloud security team is looped in and is able to confirm that the `http://169.254.169.254` endpoint is affected and that the instance’s security credentials can be obtained from the public internet.
### Notes: 
If this scenario sounds familiar, it’s because it was the root cause of several high-profile security breaches over the last few years. You’re going to need a combination of both application-level and infrastructure-level access logs to fully investigate this issue. This is also a great time to explore IMDS v2.
## AWS Account for Ransom
### Scenario: 
An engineer on your team receives an apparent ransomware email. The subject reads “We have access to your account…” and the message is from a ransomware group claiming to have compromised one of your production AWS accounts. They list the account ID and include an accurate, fairly recent, screenshot of your “EC2 instances” page as proof. Not much other information is provided, but they do mention that if they do not receive ten Bitcoins at the provided address in the next three hours, they will permanently delete all of the resources.
### Notes: 
I suspect that very few organizations would be able to handle this very high-stress situation well. While it could be possible to attempt to recover and secure the AWS account in question, the provided timeframe is too tight to do a complete audit and guarantee that the attacker does not have multiple methods of access. Hopefully your organization has business-level support with AWS and can work with them to properly lock or secure the account until a full investigation can be complete.
## Shadow AWS Accounts
### Scenario: 
Your finance team alerts you that they have observed credit card charges from “AMAZON WEB SERVICES” on several employee credit cards for the past few months. These charges appear to come from AWS accounts that have not followed the proper provisioning process. After questioning the employee’s who own the credit cards, it is revealed that at least three critical production services are running in these environments.
### Notes: 
Some security problems are technical ones and others are process-related. This scenario is very much a process one. Why are employees opening accounts on their own credit cards? Is your current provisioning process too burdensome? Is it blocking release timelines? Can you work with finance to prevent charges from AWS on individual employee’s cards?
Regardless, you must now deal with incorporating these “side” accounts into your existing infrastructure. How will you ensure that these accounts follow all of the correct onboarding procedures given that they were created outside of the standard process? Will you “lift and shift” the infrastructure into an approved account or attempt to incorporate the accounts as they are?
## Zero Day Container Vulnerabilities
### Scenario: 
A new zero day CVE in RunC is announced impacting hosts in your EKS container environments. You have over 50,000 hosts that need to be patched ASAP. Simultaneously, you need to monitor the running hosts for signs of compromise as the CVE has now been live for at least 6 hours.
### Notes: 
Depending on whether your container environments are single or multi-tenant, you may either have a big problem or a bigger problem. This particular scenario raises questions around how quickly your infrastructure updates can be tested deployed, but also around how containers, hosts, and their corresponding cloud environments (IAM access, downstream resources, etc.) can be monitored during the pre-patching period. Do you have the ability to monitor, quickly detect, and mitigate unintended IAM access from hosts that may be compromised, especially if a business decision is made not to take down the application before the patching is complete?
## Dangling Route53 Resources
### Scenario: 
You receive a report on HackerOne from a security researcher claiming that one of your organization’s subdomains is serving malware. The subdomain in question appears to have been part of a project deprecated several months ago. After further investigation, you discover that this subdomain is pointed to an S3 bucket that your application team says was deleted as part of the deprecation. Nonetheless, the domain appears active and serving traffic, so the S3 bucket must still be active… somewhere.
### Notes: 
This is a well-known security issue in AWS that works because of S3’s global namespace. Create a Route53 record, point it to an S3 bucket, delete the bucket but not the record, and an attacker can create the same bucket in their own account to serve traffic from your domain. Cleanup is fairly simple (delete the bucket), but reputational damage may persist.
## Acquired Company with No Cloud Security Policies
### Scenario: 
Your business development team informs you that at the opening of the financial quarter tomorrow morning, your company will announce that it has acquired a smaller competitor. You will be responsible for the integration and security of their cloud infrastructure. After meeting with the small team, you discover that they do not have any cloud security policies in place; their accounts have been a free-for-all for developers. Your job is now to tame this environment and bring it into compliance with your company policies.
### Notes: 
This is an incredibly complex situation that spans business, security, operations, and other departments. You may find some helpful suggestions in a prior article that I wrote: So You Inherited an AWS Account.
## Increased SES Bounce Rates
### Scenario: 
The marketing team sends you an urgent email claiming that their approved marketing emails are not being received by customers. Your organization uses AWS SES to send emails, and after checking the SES console, it is discovered that your current bounce rate had grown to 10%. Suspiciously, the sending rate had also increased to 1,000,000/day, up from the previous high of 50,000, before plummeting to 0 a few hours ago. No one in marketing claims to be sending this volume of emails, but it appears that AWS has now temporarily suspended your SES access.
### Notes: 
From a security perspective, your first priority should be to determine whether this is actually a security incident at all. Were the marketing team’s credentials or the sending platform itself compromised? Was your AWS account used with SES or a user within that account compromised? Or is this just a case of a script used by the marketing team gone awry. This is also a good time to check that your contact details are up-to-date in AWS and that your SES sending metrics are being properly monitored.
## Overprivileged Cross-Environment Jenkins
### Scenario: 
An annual compliance audit reveals that one of your application teams has been using a Jenkins instance deployed in a development account to deploy infrastructure to their development, staging, and production AWS accounts using highly-privileged credentials. Worse, this build machine is running an old version of Jenkins with a known CVE.
### Notes: 
Improved training for your developers aside, build machines are usually some of the most privileged machines in your environment. As such, they need to be more heavily secured, should not be internet facing, and should be kept up-to-date with the latest security patches. Does your organization have a team in charge of managing the build machine environment? Do you have special accounts (perhaps more carefully monitored ones) where these build machines should live? Why was this public-facing machine not discovered sooner?
## Overexposed Database
### Scenario: 
An application database was deployed in a public subnet and previously given a security “exemption” due to the use of security groups to restrict access. However, a follow-up review has revealed that the rules in this group containing CIDR blocks have grown and now exceed the network space owned by your organization by a few thousand IP addresses. No malicious activity has been detected. Your application teams are asking for an easy remediation because your organization’s IP address space exceeds the number of rules allowed by security groups.
### Notes: 
As your organization grows you may find that security solutions that were previously acceptable have now outlived their shelf life. Security groups are a common service where cracks begin to appear. At first, a few rules containing individual IP addresses are added. Then, as the list of IP addresses that need to be added exceeds 60 (the max rules allowed to be added to security groups), additional groups are created (group-a, group-b, and so on), each with 60 IPs. Eventually, that strategy fails and CIDR blocks are added `54.16.1.0/24, 54.16.2.0/24, etc`.
When you reach this point, it’s easy for a rule to accidentally overlap with a network space your organization doesn’t actually own (maybe you own `54.16.1.1–54.16.1.128`, but not `54.16.1.129` and above, and `54.16.1.0/24` over-exposes your resources). Your security team will need to be able to deliver a clear answer to the question “how can I securely allow access from our organization’s IP addresses?”
