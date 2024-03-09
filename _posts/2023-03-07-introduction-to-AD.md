---
title: "Active - Directory"
author: bakeery
description: "Introduction to Active Directory"
date: 2024-03-07 00:00:00 +0530
categories: [writeups, hackthebox]
tags: [web, tool]
---
## Introduction

Active Directory (AD) is a directory service for Windows network environments.
It is a distributed, hierarchical structure that allows for centralized management of an organization's resources, including users, computers, groups, network devices, file shares, group policies, devices, and trusts.AD provides authentication and authorization functions within a Windows domain environment. 

AD is essentially a sizeable read-only database accessible to all users within the domain, regardless of their privilege level. A basic AD user account with no added privileges can enumerate most objects within AD.
This fact makes it extremely important to properly secure an AD implementation because ANY user account, regardless of their privilege level, can be used to enumerate the domain and hunt for misconfigurations and flaws thoroughly. 

- **[2021 POC of AD](https://www.secureworks.com/blog/nopac-a-tale-of-two-vulnerabilities-that-could-end-in-ransomware)**

- **[Ransomeware that attack more than 400 ADs globally](https://www.cisa.gov/sites/default/files/publications/AA21-265A-Conti_Ransomware_TLP_WHITE.pdf )**

## Active Directory Structure

Active Directory is arranged in a hierarchical tree structure, with a forest at the top containing one or more domains, which can themselves have nested subdomains. A forest is the security boundary within which all objects are under administrative control. A forest may contain multiple domains, and a domain may include further child or sub-domains.

```
INLANEFREIGHT.LOCAL/
├── ADMIN.INLANEFREIGHT.LOCAL
│   ├── GPOs
│   └── OU
│       └── EMPLOYEES
│           ├── COMPUTERS
│           │   └── FILE01
│           ├── GROUPS
│           │   └── HQ Staff
│           └── USERS
│               └── barbara.jones
├── CORP.INLANEFREIGHT.LOCAL
└── DEV.INLANEFREIGHT.LOCAL
```
Here we could say that INLANEFREIGHT.LOCAL is the root domain and contains the subdomains (either child or tree root domains) ADMIN.INLANEFREIGHT.LOCAL, CORP.INLANEFREIGHT.LOCAL, and DEV.INLANEFREIGHT.LOCAL as well as the other objects that make up a domain such as users, groups, computers, and more 

## Active Directory Terminology
- Objects: These are entities within Active Directory, such as users, organizational units (OUs), printers, domain controllers, etc.

- Attribute: Every object in AD has a set of attributes defining its properties. Attributes provide information about objects and include LDAP names for querying. For example, a computer object may have attributes like DNS hostname.

- Schema: The schema is a blueprint defining the structure of objects in the AD environment. It contains formal definitions of object classes, including mandatory and optional attributes. For instance, the "user" class defines attributes like displayName and givenName.

- Domain: A domain is a logical grouping of objects within AD, including computers, users, OUs, and groups. It functions independently but can establish trust relationships with other domains. Think of it as a self-contained room with various functionalities.

- Forest: A forest is a collection of one or more Active Directory domains. It serves as the top-level container, encompassing all AD objects. Forests can operate independently but can be linked through trust relationships.

- Tree: A tree is a hierarchical structure within Active Directory, starting with a single root domain. Multiple domains can be organized into a tree, sharing a boundary and forming parent-child trust relationships. Each tree in a forest has its own namespace.

- Container: Containers are objects that hold other objects within the directory hierarchy. They provide a structured way to organize and manage AD resources.

- Leaf: Leaf objects are located at the end of the directory hierarchy and do not contain other objects. They represent the lowest level of organizational units within Active Directory.

- GUID (Global Unique Identifier): A unique 128-bit value assigned to each object in Active Directory. It's used for identification and cannot be changed.

- Security Principals: Entities that can be authenticated by the operating system, including users, computer accounts, and threads/processes running in a user or computer context.

- SID (Security Identifier): A unique identifier assigned to each security principal or security group. It's used for authentication and authorization.

- DN (Distinguished Name): The full path to an object in Active Directory, describing its location within the directory hierarchy.

- RDN (Relative Distinguished Name): A component of the DN that identifies an object as unique within its parent container.

- sAMAccountName: The user's logon name, limited to 20 characters and must be unique.
userPrincipalName: An alternative way to identify users in Active Directory in the format of user@domain.

- FSMO (Flexible Single Master Operation) roles: Roles assigned to domain controllers to manage specific operations within an Active Directory forest.

- Global Catalog: A domain controller that stores copies of all objects in the forest, facilitating authentication and object searches across domains.

- RODC (Read-Only Domain Controller): A domain controller with a read-only Active Directory database, suitable for branch offices or locations with limited connectivity.

- Replication: The process of transferring Active Directory objects and updates between domain controllers.

- SPN (Service Principal Name): A unique identifier for a service instance used by Kerberos authentication.

- GPO (Group Policy Object): Virtual collections of policy settings applied to user and computer objects in Active Directory.

- ACL (Access Control List): An ordered collection of ACEs (Access Control Entities) that define access rights to objects.

- DACL (Discretionary Access Control List): Part of an ACL that specifies who is allowed or denied access to an object.

- SACL (System Access Control List): Part of an ACL that determines which activities are logged for auditing purposes.

- FQDN (Fully Qualified Domain Name): The complete name for a specific computer or host in Active Directory.

- Tombstone: A container object holding deleted Active Directory objects for a specified period before permanent deletion.

- AD Recycle Bin: A feature introduced in Windows Server 2008 R2 to facilitate the recovery of deleted AD objects.

- SYSVOL: A shared folder containing Group Policy settings and logon/logoff scripts replicated to all domain controllers.

- AdminSDHolder: An object used to manage ACLs for members of built-in groups marked as privileged.

- dsHeuristics: An attribute defining multiple forest-wide configuration settings in Active Directory.

- adminCount: An attribute determining whether a user is protected by the SDProp process.

- ADUC (Active Directory Users and Computers): A GUI console for managing users, groups, computers, and contacts in Active Directory.

- ADSI Edit: A GUI tool for managing objects in Active Directory, providing access to advanced settings.

- sIDHistory: An attribute holding previously assigned SIDs for migration purposes.

- NTDS.DIT: The Active Directory database file containing AD data and password hashes.

- MSBROWSE: A Microsoft networking protocol for browsing services in LANs, identifying the Master Browser.

## Object Types in Active Directory:

- Users: Represent individuals within the organization. They have various attributes like display name, email address, etc.

- Contacts: Typically used for external users or entities. They contain information such as name, email, and phone number.

- Printers: Point to printers accessible within the AD network and contain attributes like printer name and driver information.

- Computers: Represent computers joined to the AD network, such as workstations or servers. They have security identifiers (SIDs) and global unique identifiers (GUIDs).

- Shared Folders: Point to shared folders on specific computers and have access control settings.

- Groups: Container objects that can hold users, computers, or other groups. They are security principals and have SIDs and GUIDs.

- Organizational Units (OUs): Containers used for organizing similar objects for administrative purposes, facilitating delegation of tasks.

- Domains: The structure of an AD network containing objects like users and computers, each with its own database and policies.

- Domain Controllers: Responsible for authentication, user verification, and access control within the domain.

- Sites: Sets of computers across subnets connected by high-speed links, used for efficient replication.

- Built-in: Container holding default groups created with the AD domain.

- Foreign Security Principals (FSPs): Created in AD to represent security principals from trusted external forests.

## Authentication and Authorization Protocols:

1. Kerberos:
    - Kerberos is an authentication protocol used in Active Directory environments.
    - It provides mutual authentication between clients and servers without transmitting passwords over the network.
    - The Kerberos authentication process involves obtaining tickets from a Key Distribution Center (KDC).
    - It uses tickets for authentication instead of transmitting user passwords directly.
    - Kerberos operates on port 88 and is a stateless protocol.

2. DNS (Domain Name System):
    - DNS is used in Active Directory to locate Domain Controllers and for communication among them.
    - It resolves hostnames to IP addresses and vice versa.
    - Active Directory DNS namespaces facilitate communication within the network.
    - Service records (SRV) in DNS enable clients to locate necessary services like Domain Controllers.

3. LDAP (Lightweight Directory Access Protocol):
    - LDAP is used for directory lookups and authentication against Active Directory.
    - It operates on port 389, while LDAP over SSL (LDAPS) uses port 636 for secure communication.
    - LDAP authentication involves BIND operations to set authentication states.
    - There are two types of LDAP authentication: Simple Authentication and SASL Authentication.

4. NTLM (NT LAN Manager):
    - NTLM is an authentication protocol used alongside Kerberos in Active Directory environments.
    - It utilizes challenge-response authentication and uses three messages to authenticate clients.
    - NTLM hashes are used for password storage in modern Windows systems.
    - NTLM hashes can be cracked offline, making them susceptible to attacks like pass-the-hash.

5. NTLMv1 and NTLMv2:
    - NTLMv1 and NTLMv2 are variations of the NTLM protocol.
    - NTLMv1 uses both the LM and NT hash for authentication and is susceptible to cracking.
    - NTLMv2 is a stronger alternative introduced in Windows NT 4.0 SP4.
    - NTLMv2 sends two responses to the server's challenge, enhancing security compared to NTLMv1.
    
6. Domain Cached Credentials (DCC), also known as MSCache2:
   - DCC is an authentication mechanism developed by Microsoft.
   - It allows domain-joined hosts to store the last ten hashes of successfully logged-in domain users.
   - Stored in the registry, these hashes cannot be used in pass-the-hash attacks.
   - Despite being slow to crack, understanding DCC hashes is crucial for effective assessment of AD environments by penetration testers