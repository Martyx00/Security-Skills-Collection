import java.security.MessageDigest;
import java.sql.Statement;

public class Svc {
    static byte[] digest(byte[] d) throws Exception {           // EXPECT-FUNC: digest
        return MessageDigest.getInstance("MD5").digest(d);      // EXPECT: CRY-002
    }

    static void query(Statement s, String name) throws Exception {   // EXPECT-FUNC: query
        s.executeQuery("SELECT * FROM t WHERE n='" + name + "'");    // EXPECT: INJ-003
    }

    static void run(String u) throws Exception {                // EXPECT-FUNC: run
        Runtime.getRuntime().exec(u);                           // EXPECT: INJ-002
    }

    static Object load(byte[] b) throws Exception {             // EXPECT-FUNC: load
        return new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(b)).readObject();  // EXPECT: LOG-006
    }

    // Appended below so that nothing citing the lines above moves.

    static byte[] sha1(byte[] d) throws Exception {             // EXPECT-FUNC: sha1
        return MessageDigest.getInstance("SHA-1").digest(d);    // EXPECT: CRY-002
    }

    static javax.crypto.Cipher tdes() throws Exception {        // EXPECT-FUNC: tdes
        return javax.crypto.Cipher.getInstance("DESede/CBC/PKCS5Padding");  // EXPECT: CRY-002
    }

    static java.io.InputStream openDoc(String name) throws Exception {  // EXPECT-FUNC: openDoc
        return new java.io.FileInputStream("/srv/docs/" + name);        // EXPECT: INJ-004
    }

    static java.io.InputStream download(String u) throws Exception {    // EXPECT-FUNC: download
        return new java.net.URL(u).openConnection().getInputStream();   // EXPECT: INJ-005
    }

    static int purge(Statement s, String name) throws Exception {       // EXPECT-FUNC: purge
        return s.executeUpdate("delete from t where n = '" + name + "'");  // EXPECT: INJ-003
    }
}

// Appended below so that nothing citing the lines above moves. `new URL(u)`
// only parses, in Java as in JavaScript; the request is the stream it opens.
class Fetch {
    static java.io.InputStream fetchStream(java.net.URL url) throws Exception {   // EXPECT-FUNC: fetchStream
        return url.openStream();                                                 // EXPECT: INJ-005
    }
}

// Appended below so that nothing citing the lines above moves. The logic-flaw
// rules asserted in one language until now.
class Guard {
    boolean isAuthenticated(Object s) {                                 // EXPECT-FUNC: isAuthenticated  // EXPECT: LOG-001
        return s != null;
    }

    boolean hasPermission(Object u, Object o) {                         // EXPECT-FUNC: hasPermission  // EXPECT: LOG-002
        return u == o;
    }

    byte[] encryptBlock(byte[] b) {                                     // EXPECT-FUNC: encryptBlock  // EXPECT: LOG-003
        return b;
    }

    boolean isValid(String s) {                                         // EXPECT-FUNC: isValid  // EXPECT: LOG-010
        return s != null;
    }
}

// Appended below so that nothing citing the lines above moves. A trust manager:
// an empty checkServerTrusted is the whole of that bug, so its name is what
// selects it. And BigInteger's modPow, which RSA in Java is written with.
class TrustAll {
    public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {   // EXPECT-FUNC: checkServerTrusted  // EXPECT: LOG-004
    }
}

class BigMath {
    java.math.BigInteger modPow(java.math.BigInteger b, java.math.BigInteger e, java.math.BigInteger m) {   // EXPECT-FUNC: modPow  // EXPECT: LOG-007
        return b.modPow(e, m);
    }
}
