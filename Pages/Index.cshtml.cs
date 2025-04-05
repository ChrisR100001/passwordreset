using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using PasswordResetPortal;
using System;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

public class IndexModel : PageModel
{
    [BindProperty] public string Username { get; set; }  // domain\username or username@domain.com
    [BindProperty] public string OldPassword { get; set; }
    [BindProperty] public string NewPassword { get; set; }
    [BindProperty] public string ConfirmPassword { get; set; }

    public string Message { get; set; }

    private readonly IConfiguration _config;

    public IndexModel(IConfiguration config)
    {
        _config = config;
    }

    public void OnGet() { }

    public void OnPost()
    {
        if (NewPassword != ConfirmPassword)
        {
            Message = "New passwords do not match.";
            return;
        }

        try
        {
            // 🔧 CONFIG: Your domain controller and LDAP base
            string domainController = _config["DomainController"]; ; // FQDN or IP of your domain controller
            string ldapBase = _config["DomainLdapBase"];
            var serviceUser = _config["ServiceAccount:UserUpn"];
            var servicePasswordEnc = _config["ServiceAccount:UserPassword"];
            var servicePassword = SecurityHelper.Decrypt(servicePasswordEnc, "passwordresetportal");

            string samAccountName = ExtractSamAccountName(Username);

            string userDn = GetUserDistinguishedName(domainController, ldapBase, samAccountName);
            if (userDn == null)
            {
                if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    EventLog.WriteEntry("PasswordResetPortal", $"Received invalid username {Username}", EventLogEntryType.Information);

                Message = "❌ Current password is incorrect or invalid user name.";
                return;
            }

            bool passwordChangeRequired;
            if (!ValidateUserCredentials(domainController, userDn, OldPassword, out passwordChangeRequired))
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    EventLog.WriteEntry("PasswordResetPortal", $"Received invalid password for username {Username}", EventLogEntryType.Information);

                Message = "❌ Current password is incorrect or invalid user name.";
                return;
            }

            // Step 2: Change password using service account
            string result = ChangeUserPasswordAsService(domainController, serviceUser, servicePassword, userDn, NewPassword);
            
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                EventLog.WriteEntry("PasswordResetPortal", $"Changed password for username {Username}", EventLogEntryType.Information);

            Message = result;

        }
        catch (Exception ex)
        {
            Message = $"Error: {ex.Message}";
        }
    }

    private bool ValidateUserCredentials(string domainController, string userDn, string password, out bool passwordChangeRequired)
    {
        passwordChangeRequired = false;

        try
        {
            var credential = new NetworkCredential(userDn, password);
            var identifier = new LdapDirectoryIdentifier(domainController, 636);
            using (var conn = new LdapConnection(identifier, credential, AuthType.Basic))
            {
                conn.SessionOptions.ProtocolVersion = 3;
                conn.SessionOptions.SecureSocketLayer = true;
                conn.SessionOptions.VerifyServerCertificate += (c, cert) => true;

                conn.Bind(); // Will fail if password is wrong
                return true;
            }
        }
        catch(LdapException ex)
        {
            if (!string.IsNullOrEmpty(ex.ServerErrorMessage))
            {
                if (ex.ServerErrorMessage.Contains("data 773"))
                {
                    passwordChangeRequired = true;
                    return true; // password is correct, bind was blocked by password reset requirement
                }
                else if (ex.ServerErrorMessage.Contains("data 52e"))
                {
                    return false; // invalid credentials
                }
            }

            //Default to return false for other error conditions
            return false;
        }
    }

    private string ChangeUserPasswordAsService(string domainController, string serviceUsername, string servicePassword, string userDn, string newPassword)
    {
        var identifier = new LdapDirectoryIdentifier(domainController, 636);
        var credential = new NetworkCredential(serviceUsername, servicePassword);

        using (var connection = new LdapConnection(identifier, credential, AuthType.Basic))
        {
            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.SecureSocketLayer = true;
            connection.SessionOptions.VerifyServerCertificate += (conn, cert) => true;

            connection.Bind();

            var mod = new DirectoryAttributeModification
            {
                Name = "unicodePwd",
                Operation = DirectoryAttributeOperation.Replace
            };
            mod.Add(EncodePassword(newPassword));

            var request = new ModifyRequest(userDn, mod);

            try
            {
                connection.SendRequest(request);
                return "✅ Password successfully changed.";
            }
            catch (DirectoryOperationException ex)
            {
                // Specific for password policy failure
                if (ex.Message.Contains("0000052D") || ex.Message.Contains("WILL_NOT_PERFORM"))
                {
                    return "❌ Password does not meet password complexity requirements. Please ensure that it is at least 8 characters long and includes numbers and symbols. For specific reqwuirements please contact your network administrator.";
                }

                return $"❌ Directory error: {ex.Message}";
            }
            catch (Exception ex)
            {
                return $"❌ General error: {ex.Message}";
            }
        }
    }

    private string ExtractSamAccountName(string input)
    {
        if (!string.IsNullOrEmpty(input))
        {
            if (input.Contains("\\"))
                return input.Split('\\')[1];
            if (input.Contains("@"))
                return input.Split('@')[0];
            return input;
        }

        return "";
    }

    private string GetUserDistinguishedName(string domainController, string ldapBase, string username)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))  //This only works on Windows
        {
            var entry = new DirectoryEntry($"LDAP://{domainController}/{ldapBase}");
            var searcher = new DirectorySearcher(entry)
            {
                Filter = $"(sAMAccountName={username})"
            };
            searcher.PropertiesToLoad.Add("distinguishedName");
            var result = searcher.FindOne();
            if (result != null)
            {
                return result.Properties["distinguishedName"][0]?.ToString(); // ✅ This is what LDAP expects
            }
        }
        return null;
    }


    private string ChangePassword(string domainController, string userDn, string oldPassword, string newPassword)
    {
        var identifier = new LdapDirectoryIdentifier(domainController, 636, false, false);
        var credential = new NetworkCredential(userDn, oldPassword);

        using (var connection = new LdapConnection(identifier, credential, AuthType.Basic))
        {
            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.SecureSocketLayer = true;
            connection.SessionOptions.VerifyServerCertificate += (conn, cert) => true;

            try
            {
                // ⚠️ Don't explicitly call connection.Bind() — just go straight to ModifyRequest
                var deleteMod = new DirectoryAttributeModification
                {
                    Name = "unicodePwd",
                    Operation = DirectoryAttributeOperation.Delete
                };
                deleteMod.Add(EncodePassword(oldPassword)); // DO NOT quote again here

                var addMod = new DirectoryAttributeModification
                {
                    Name = "unicodePwd",
                    Operation = DirectoryAttributeOperation.Add
                };
                addMod.Add(EncodePassword(newPassword));

                var request = new ModifyRequest(userDn, deleteMod, addMod);
                connection.SendRequest(request);

                return "✅ Password successfully changed.";
            }
            catch (DirectoryOperationException ex)
            {
                return $"❌ Password change failed: {ex.Message}\nDetails: {ex.Response?.ErrorMessage}";
            }
            catch (LdapException ex)
            {
                return $"❌ LDAP error: {ex.Message}";
            }
            catch (Exception ex)
            {
                return $"❌ General error: {ex.Message}";
            }
        }
    }


    private byte[] EncodePassword(string password)
    {
        return Encoding.Unicode.GetBytes($"\"{password}\"");
    }
}
