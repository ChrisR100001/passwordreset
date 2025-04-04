using System;
using System.Net;
using System.DirectoryServices.Protocols;

namespace PasswordResetPortal
{
    public static class LdapAuthHelper
    {
        public static string TryBindAndExplain(string domainController, string username, string password)
        {
            try
            {
                var identifier = new LdapDirectoryIdentifier(domainController);
                using (var connection = new LdapConnection(identifier, new NetworkCredential(username, password)))
                {
                    connection.AuthType = AuthType.Negotiate;
                    connection.Bind(); // Attempt bind
                    return "Bind successful.";
                }
            }
            catch (LdapException ex)
            {
                return $"LDAP Exception: {ex.Message} (ErrorCode: {ex.ErrorCode})";
            }
            catch (Exception ex)
            {
                return $"General Exception: {ex.Message}";
            }
        }
    }
    public static class LdapPasswordChanger
    {
        public static string ChangePassword(
            string domainController,
            string userDn, // e.g. "CN=John Smith,OU=Users,DC=domain,DC=com"
            string oldPassword,
            string newPassword)
        {
            try
            {
                var identifier = new LdapDirectoryIdentifier(domainController, 389);
                var credential = new NetworkCredential(userDn, oldPassword);

                using (var connection = new LdapConnection(identifier, credential, AuthType.Basic))
                {
                    connection.SessionOptions.ProtocolVersion = 3;
                    connection.Bind(); // attempt bind as user (even if "must change password" is set)

                    var request = new ModifyRequest(userDn,
                        DirectoryAttributeOperation.Delete, "unicodePwd", EncodePassword($"\"{oldPassword}\""),
                        DirectoryAttributeOperation.Add, "unicodePwd", EncodePassword($"\"{newPassword}\"")
                    );

                    connection.SendRequest(request);

                    return "Password successfully changed.";
                }
            }
            catch (DirectoryOperationException ex)
            {
                return $"Directory error: {ex.Message}\nServer Message: {ex.Response?.ErrorMessage}";
            }
            catch (LdapException ex)
            {
                return $"LDAP error: {ex.Message}";
            }
            catch (Exception ex)
            {
                return $"General error: {ex.Message}";
            }
        }

        private static byte[] EncodePassword(string password)
        {
            return System.Text.Encoding.Unicode.GetBytes(password);
        }
    }
}
