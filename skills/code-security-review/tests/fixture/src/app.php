<?php
// PHP: the web idioms a ruleset transcribed from C never saw.

function run_tool($dir) {                                   // EXPECT-FUNC: run_tool
    exec("ls " . $dir, $out);                               // EXPECT: INJ-002
    return `cat $dir`;                                      // EXPECT: INJ-002
}

function find_user($pdo, $id) {                             // EXPECT-FUNC: find_user
    return $pdo->query('SELECT * FROM users WHERE id = ' . $id);   // EXPECT: INJ-003
}

function find_order($conn, $id) {                           // EXPECT-FUNC: find_order
    return mysqli_query($conn, "SELECT * FROM orders WHERE id = $id");   // EXPECT: INJ-003
}

function read_doc($name) {                                  // EXPECT-FUNC: read_doc
    return file_get_contents("/srv/docs/" . $name);         // EXPECT: INJ-004
}

function render($page) {                                    // EXPECT-FUNC: render
    include $page;                                          // EXPECT: INJ-004
}

function fetch_url($u) {                                    // EXPECT-FUNC: fetch_url
    $ch = curl_init($u);                                    // EXPECT: INJ-005
    return curl_exec($ch);
}

function digest($d) {                                       // EXPECT-FUNC: digest
    return md5($d);                                         // EXPECT: CRY-002
}

function insecure_get($client, $u) {                        // EXPECT-FUNC: insecure_get
    return $client->get($u, ['verify' => false]);           // EXPECT: CRY-004
}

function load($blob) {                                      // EXPECT-FUNC: load
    return unserialize($blob);                              // EXPECT: LOG-006
}

$password = "hunter2-not-a-real-one";                       // EXPECT: LOG-005

// Appended below so that nothing citing the lines above moves.
// The textbook local-file inclusion: the variable is concatenated into the
// path, so no `$` follows the keyword directly.
function render_named($name) {                             // EXPECT-FUNC: render_named
    include("pages/" . $name . ".php");                     // EXPECT: INJ-004
}

function load_lang($lang) {                                 // EXPECT-FUNC: load_lang
    require_once __DIR__ . '/lang/' . $lang . '.php';       // EXPECT: INJ-004
}

// Appended below so that nothing citing the lines above moves.
function wp_signon($creds) {                                // EXPECT-FUNC: wp_signon // EXPECT: LOG-001
    return $creds;
}

// openssl_verify returns -1 on error, which PHP reads as true.
function license_ok($data, $sig, $key) {                    // EXPECT-FUNC: license_ok
    if (openssl_verify($data, $sig, $key)) {                // EXPECT: LOG-004
        return true;
    }
    return false;
}

function token_matches($token) {                            // EXPECT-FUNC: token_matches
    return $_GET['token'] == $token;                        // EXPECT: LOG-008
}

// libsodium's PHP binding opens with sodium_, a prefix the sink half's call
// context once read as no call; it returns false on a bad signature.
function load_message($signed, $pk) {                       // EXPECT-FUNC: load_message
    $msg = sodium_crypto_sign_open($signed, $pk);           // EXPECT: LOG-004
    return json_decode($msg, true);
}
