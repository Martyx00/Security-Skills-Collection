# Ruby: backticks, Kernel#exec and SQL built by interpolation.
require "digest"
require "net/http"

def run_tool(dir)                                           # EXPECT-FUNC: run_tool
  exec("ls #{dir}")                                         # EXPECT: INJ-002
end

def list(dir)                                               # EXPECT-FUNC: list
  `ls #{dir}`                                               # EXPECT: INJ-002
end

def find_user(id)                                           # EXPECT-FUNC: find_user
  User.find_by_sql("SELECT * FROM users WHERE id = #{id}")  # EXPECT: INJ-003
end

def read_doc(name)                                          # EXPECT-FUNC: read_doc
  File.read("/srv/docs/" + name)                            # EXPECT: INJ-004
end

def fetch_url(u)                                            # EXPECT-FUNC: fetch_url
  Net::HTTP.get(URI(u))                                     # EXPECT: INJ-005
end

def digest(d)                                               # EXPECT-FUNC: digest
  Digest::MD5.hexdigest(d)                                  # EXPECT: CRY-002
end

def insecure(http)                                          # EXPECT-FUNC: insecure
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE              # EXPECT: CRY-004
end

def load(blob)                                              # EXPECT-FUNC: load
  Marshal.load(blob)                                        # EXPECT: LOG-006
end

def token(max)                                              # EXPECT-FUNC: token
  rand(max)                                                 # EXPECT: OTH-002
end

# A method defined without parentheses. The candidate gate looked for
# `purge(` in the file and refused the run; `def token(max)` above was
# written with them to get past it.
def purge                                                   # EXPECT-FUNC: purge
  system("rm -rf /srv/cache/" + ENV["CACHE_DIR"])           # EXPECT: INJ-002
end

# Appended below so that nothing citing the lines above moves. The logic-flaw
# rules asserted in one language until now, as a Rails app spells them.
def require_login                                           # EXPECT-FUNC: require_login  # EXPECT: LOG-001
  session[:user_id]
end

def require_admin                                           # EXPECT-FUNC: require_admin  # EXPECT: LOG-002
  current_user.admin
end

def hmac_digest(key, data)                                  # EXPECT-FUNC: hmac_digest  # EXPECT: LOG-003
  OpenSSL::HMAC.digest("SHA256", key, data)
end

# Appended below so that nothing citing the lines above moves. Devise's
# sign_out, Psych's YAML.load and Rails' secret_key_base.
def sign_out                                                # EXPECT-FUNC: sign_out  # EXPECT: LOG-009
  reset_session
end

def load_doc(doc)                                           # EXPECT-FUNC: load_doc
  YAML.load(doc)                                            # EXPECT: LOG-006
end

def configure(config)                                       # EXPECT-FUNC: configure
  config.secret_key_base = "a1b2c3d4e5f6-not-a-real-one"    # EXPECT: LOG-005
end
