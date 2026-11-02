// C#: the .NET spellings of the same families.
using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;

public class Handler
{
    public static byte[] Digest(byte[] d)                           // EXPECT-FUNC: Digest
    {
        return MD5.Create().ComputeHash(d);                         // EXPECT: CRY-002
    }

    public static void Run(string arg)                              // EXPECT-FUNC: Run
    {
        Process.Start("tool", arg);                                 // EXPECT: INJ-002
    }

    public static string Query(string name)                         // EXPECT-FUNC: Query
    {
        return "SELECT * FROM t WHERE n='" + name + "'";            // EXPECT: INJ-003
    }

    public static string ReadDoc(string name)                       // EXPECT-FUNC: ReadDoc
    {
        return File.ReadAllText(Path.Combine("/srv/docs", name));   // EXPECT: INJ-004
    }

    public static HttpResponseMessage Fetch(HttpClient c, string u) // EXPECT-FUNC: Fetch
    {
        return c.GetAsync(u).Result;                                // EXPECT: INJ-005
    }

    public static HttpClientHandler Insecure()                      // EXPECT-FUNC: Insecure
    {
        var h = new HttpClientHandler();
        h.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true;   // EXPECT: CRY-004
        return h;
    }

    public static int Token()                                       // EXPECT-FUNC: Token
    {
        return new Random().Next();                                 // EXPECT: OTH-002
    }
}

// Appended below so that nothing citing the lines above moves.
public class Account
{
    public bool PasswordSignIn(string u, string p)                  // EXPECT-FUNC: PasswordSignIn  // EXPECT: LOG-001
    {
        return u.Length > p.Length;
    }

    public bool IsInRole(string role)                               // EXPECT-FUNC: IsInRole  // EXPECT: LOG-002
    {
        return role.Length > 0;
    }
}

// Appended below so that nothing citing the lines above moves. .NET
// capitalises Verify.
public class License
{
    public static bool CheckLicense(RSA rsa, byte[] data, byte[] sig)   // EXPECT-FUNC: CheckLicense
    {
        return rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);   // EXPECT: LOG-004
    }
}
