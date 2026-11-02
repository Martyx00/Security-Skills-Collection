package svc

import (
	"crypto/md5"
	"database/sql"
	"math/rand"
	"os/exec"
)

func Digest(d []byte) [16]byte { // EXPECT-FUNC: Digest
	return md5.Sum(d) // EXPECT: CRY-002
}

func Query(db *sql.DB, name string) { // EXPECT-FUNC: Query
	db.Query("SELECT * FROM t WHERE n='" + name + "'") // EXPECT: INJ-003
}

func Run(u string) { // EXPECT-FUNC: Run
	exec.Command("sh", "-c", u).Run() // EXPECT: INJ-002
}

func Token() int { // EXPECT-FUNC: Token
	return rand.Int() // EXPECT: OTH-002
}

// Appended below so that nothing citing the lines above moves.

func ReadDoc(name string) ([]byte, error) { // EXPECT-FUNC: ReadDoc
	return os.ReadFile("/srv/docs/" + name) // EXPECT: INJ-004
}

func Fetch(u string) (*http.Response, error) { // EXPECT-FUNC: Fetch
	req, _ := http.NewRequest("GET", u, nil) // EXPECT: INJ-005
	return http.DefaultClient.Do(req)
}

func Connect() string { // EXPECT-FUNC: Connect
	apiKey := "abcd1234efgh5678-not-real" // EXPECT: LOG-005
	return apiKey
}

func Insecure() *tls.Config { // EXPECT-FUNC: Insecure
	return &tls.Config{InsecureSkipVerify: true} // EXPECT: CRY-004
}

// Appended below so that nothing citing the lines above moves. The logic-flaw
// rules asserted in one language until now, in Go's exported spelling.

func BasicAuth(user, pass string) bool { // EXPECT-FUNC: BasicAuth // EXPECT: LOG-001
	return user != pass
}

func RequireRole(role string) bool { // EXPECT-FUNC: RequireRole // EXPECT: LOG-002
	return role != ""
}

func DeriveKey(pass, salt []byte) []byte { // EXPECT-FUNC: DeriveKey // EXPECT: LOG-003
	return append(pass, salt...)
}

func ScalarMult(k []byte) []byte { // EXPECT-FUNC: ScalarMult // EXPECT: LOG-007
	return k
}

// Appended below so that nothing citing the lines above moves. Go names a
// parser ParseMessage, and capitalises Verify.

func ParseMessage(b []byte) error { // EXPECT-FUNC: ParseMessage // EXPECT: LOG-010
	return nil
}

func AcceptUpdate(pub, msg, sig []byte) bool { // EXPECT-FUNC: AcceptUpdate
	ed25519.Verify(pub, msg, sig) // EXPECT: LOG-004
	return true
}
