# 🔐 Password Reset Portal

A secure self-service password reset portal for internal staff.  

## 🚀 Overview

This web application allows employees to safely reset their account passwords through an easy-to-use interface. It integrates with Active Directory.

Key features include:
- Integration-ready with Active Directory or LDAP
- Only runs on Windows operating system

## 🛠 Tech Stack

- **Backend**: ASP.NET Core (.NET 6/7)
- **Hosting**: IIS (in-process model)
- **Deployment**: Windows Server
- **Logging**: Integrated with stdout and system event logs
- **Security**: TLS enforced via IIS

## 📂 Project Structure

/PasswordResetPortal 
│ 
├── Controllers/ # API controllers 
├── Models/ # Request/response models 
├── Views/ # Razor views 
├── wwwroot/ # Static assets 
├── Program.cs # Entry point 
└── appsettings.json # Configuration settings


## 🔧 Deployment Notes

### IIS Setup

1. Ensure the **.NET Core Hosting Bundle** is installed.
2. Place the published output in `D:\WWWROOT\server.exampledomain.co.uk\site`.
3. Configure a **binding** in IIS with an SSL certificate issued for `server.exampledomain.co.uk`.
4. The `web.config` file should point to the DLL:

    <aspNetCore processPath="dotnet" arguments=".\PasswordResetPortal.dll" hostingModel="inprocess" />

5. With an elevated command prompt, run the PasswordResetPortal.exe binary - this will register the PasswordResetPortal event log source on Windows platform.

### Troubleshooting

    500.19 Error: Likely caused by malformed web.config or missing .NET Hosting Bundle.
    DLL Not Found: Confirm PasswordResetPortal.dll is present in the deployment directory.
    SSL Issues: Verify the certificate in IIS is correctly installed and bound to the hostname.

### Service Account

In order to reset passwords of accounts that have the "User must change password" flag set a service account is required.
This account needs to be given delegated rights to reset passwords for the OUs in Active Directory that contain the users that
will be using this app.  Although an administrator account can be used it is better practice to create a dedicated service account
that only has the change password delegated privileges granted.

The service account credentials need to be stored in the appsettings.json file.  For security, the password is encrypted.

    {
      "Logging": {
        "LogLevel": {
        "Default": "Information",
        "Microsoft.AspNetCore": "Warning"
    }
    },
    "AllowedHosts": "*",

    "ServiceAccount": {
      "UserUpn": "svc_account@exampledomain.co.uk",
      "UserPassword": "1xQHCci5YpolO3La3YQ9/+D3Wlwtaf8l8FkoXPn9ayg="
    },
    "Domain": "exampledomain.co.uk",
    "DomainController": "dchost.exampledomain.co.uk",
    "DomainLdapBase": "DC=exampledomain,DC=co,DC=uk"
    }


Set the name of the service account you have created in the UserUpn field and use the app to encrypt the password for this account 
using /encryptpass page.  This page accepts a password in plain text and will generate the enrypted value that you can store in the appsettings.json file

### LDAPS

This software requires that LDAPS is configured on your domain controller.  This is not done by default and will
need to be undertaken.  This guide was based on documentation from Microsoft and some further research.  I found that
the request has to be generated from Windows, requests generated through other mechanisms appear to be incompatible with NTDS.

1) Create a request.inf text file

        ;----------------- request.inf -----------------
        [Version]

        Signature="$Windows NT$

        [NewRequest]

        Subject = "CN=host.exampledomain.co.uk" ; replace with the FQDN of the DC
        KeySpec = 1
        KeyLength = 2048
        HashAlgorithm = sha256
        ; Can be 1024, 2048, 4096, 8192, or 16384.
        ; Larger key sizes are more secure, but have
        ; a greater impact on performance.
        Exportable = TRUE
        MachineKeySet = TRUE
        SMIME = False
        PrivateKeyArchive = FALSE
        UserProtected = FALSE
        UseExistingKeySet = FALSE
        ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
        ProviderType = 12
        RequestType = PKCS10
        KeyUsage = 0xa0

        [EnhancedKeyUsageExtension]

        OID=1.3.6.1.5.5.7.3.1 ; this is for Server Authentication

        ;-----------------------------------------------

2) From an elevated prompt run

    certreq -new request.inf request.req

This will generate  a CSR file called request.req

3) Have the CSR signed by a CA - this might be an internal one - if so ensure that the CA certificate is installed in the machine "Trusted Root Certification Authorities"
store. Place the resulting certificate in a text file in same folder as the req was generated.

4) Run

    certreq -accept filename.crt

    C:\Users\user>certreq -accept host.exampledomain.co.uk.crt
    Installed Certificate:
      Serial Number: 77
      Subject: CN=host.exampledomain.co.uk
      NotBefore: 04/04/2025 12:51
      NotAfter: 04/04/2026 12:51
      Thumbprint: bda7974788f39577e724ecbd00fb844d6bedf721

  At this point the certificate (and it's private key will be installed in the Local machine Personal keystore). This is all that is required.

  Restart the "Active Directory Domain Services" service on the domain controller.  You can check the event log (System) for any errors relating to NTDS - if the certificate can't be bound, these errors will appear here.

  5) Validate that you can connect to LDAPS.  Launch ldp.exe.  Click on Connection then Connect and enter your domain controller host name and enter port 636 and ensure SSL check box is checked.

  Click OK to connect and you should see a screen full of text.  If there are only four lines with error on them then something has not worked and you will need to troubleshoot.

  The NTDS service will look in the Local Machine "Personal" keystore for certificates (with private keys) that have a CN that matches the server.  I have found that having SAN fields set is not required and may be a problem.

  **THE END**