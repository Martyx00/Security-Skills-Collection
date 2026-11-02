// JavaScript: the eval/require family, and a lowercase digest name.
const crypto = require('crypto');

function digest(d) {                                    // EXPECT-FUNC: digest
  return crypto.createHash('md5').update(d).digest();   // EXPECT: CRY-002
}

function evaluate(src) {                                // EXPECT-FUNC: evaluate
  return eval(src);                                     // EXPECT: INJ-002
}

function query(db, name) {                              // EXPECT-FUNC: query
  return db.query("SELECT * FROM t WHERE n='" + name + "'");  // EXPECT: INJ-003
}

function token() {                                      // EXPECT-FUNC: token
  return Math.random().toString(36);                    // EXPECT: OTH-002
}

const password = "hunter2-not-a-real-one";            // EXPECT: LOG-005

function verifySig(sig, expected) {                   // EXPECT-FUNC: verifySig  // EXPECT: LOG-004
  return sig === expected;                            // EXPECT: LOG-008
}

// Appended below so that nothing citing the lines above moves.

const { exec } = require('child_process');

function listDir(dir, cb) {                             // EXPECT-FUNC: listDir
  exec('ls ' + dir, cb);                                // EXPECT: INJ-002
}

function findUser(db, id) {                             // EXPECT-FUNC: findUser
  return db.query(`SELECT * FROM users WHERE id = ${id}`);   // EXPECT: INJ-003
}

function findOrder(db, id) {                            // EXPECT-FUNC: findOrder
  return db.query('SELECT * FROM orders WHERE id = ' + id);  // EXPECT: INJ-003
}

function readDoc(name) {                                // EXPECT-FUNC: readDoc
  return require('fs').readFileSync('/srv/docs/' + name);    // EXPECT: INJ-004
}

function proxy(url) {                                   // EXPECT-FUNC: proxy
  return axios.get(url);                                // EXPECT: INJ-005
}

function insecureAgent(https) {                         // EXPECT-FUNC: insecureAgent
  return new https.Agent({ rejectUnauthorized: false });     // EXPECT: CRY-004
}

// The Express handler shapes. Stage 1 names an async arrow after its
// binding and calls an unbound callback <anonymous>, and the candidate
// gate has to accept both. The regex literal holds `//`, which a comment
// mask would read as the rest of the line, taking the `}` with it: the
// function would then run to the end of the file and be dropped unclosed.

const runCode = async (req, res) => {                   // EXPECT-FUNC: runCode
  res.send(String(eval(req.query.code)));               // EXPECT: INJ-002
};

app.get('/x', function (req, res) {
  res.send(String(eval(req.query.expr)));               // EXPECT: INJ-002
});

function fetchChecked(u) {                              // EXPECT-FUNC: fetchChecked
  if (u) { u = /^https?:\/\//.test(u) ? u : ''; }
  return u ? axios.get(u) : eval(u);                    // EXPECT: INJ-002, INJ-005
}

// Appended below so that nothing citing the lines above moves. jwt.verify
// inside a function LOG-004's name half does not select, so only its line
// half can meet the expectation.

function requireSession(req, res, next) {                  // EXPECT-FUNC: requireSession
  const claims = jwt.verify(req.headers.token, process.env.SECRET);   // EXPECT: LOG-004
  next(claims);
}

function sanitizeHtml(s) {                                  // EXPECT-FUNC: sanitizeHtml  // EXPECT: LOG-010
  return s;
}

// Appended below so that nothing citing the lines above moves. Express's login
// and logout middleware.

function isLoggedIn(req, res, next) {                       // EXPECT-FUNC: isLoggedIn  // EXPECT: LOG-001
  return next();
}

function handleLogout(req, res) {                           // EXPECT-FUNC: handleLogout  // EXPECT: LOG-009
  req.session.destroy();
}
