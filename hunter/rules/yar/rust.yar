// Rust install and runtime hooks. Text only: nothing here is compiled or run.
// comments = "skip" so a // line that mentions a token is not a hit.

rule rs_build_fetch_exec
{
  meta:
    tier = "weak"
    scope = "rust_build"
    eco = "crates"
    comments = "skip"
    summary = "build.rs downloads with an HTTP client and starts a process within 400 bytes."
  strings:
    $get = "ureq::get" ascii
    $upost = "ureq::post" ascii
    $rget = "reqwest::get" ascii
    $client = "reqwest::Client" ascii
    $atto = "attohttpc::" ascii
    $mini = "minreq::get" ascii
    $isahc = "isahc::" ascii
    $cmd = "Command::new" ascii
  condition:
    (
      for any i in (1 .. #get) : ( $cmd in (@get[i] .. @get[i] + 400) ) or
      for any i in (1 .. #upost) : ( $cmd in (@upost[i] .. @upost[i] + 400) ) or
      for any i in (1 .. #rget) : ( $cmd in (@rget[i] .. @rget[i] + 400) ) or
      for any i in (1 .. #client) : ( $cmd in (@client[i] .. @client[i] + 400) ) or
      for any i in (1 .. #atto) : ( $cmd in (@atto[i] .. @atto[i] + 400) ) or
      for any i in (1 .. #mini) : ( $cmd in (@mini[i] .. @mini[i] + 400) ) or
      for any i in (1 .. #isahc) : ( $cmd in (@isahc[i] .. @isahc[i] + 400) ) or
      for any i in (1 .. #cmd) : (
        $get in (@cmd[i] .. @cmd[i] + 400) or
        $upost in (@cmd[i] .. @cmd[i] + 400) or
        $rget in (@cmd[i] .. @cmd[i] + 400) or
        $client in (@cmd[i] .. @cmd[i] + 400) or
        $atto in (@cmd[i] .. @cmd[i] + 400) or
        $mini in (@cmd[i] .. @cmd[i] + 400) or
        $isahc in (@cmd[i] .. @cmd[i] + 400)
      )
    )
}

rule rs_fetch_exec
{
  meta:
    tier = "weak"
    scope = "rust"
    eco = "crates"
    comments = "skip"
    summary = "Rust source downloads with an HTTP client and starts a process within 400 bytes."
  strings:
    $get = "ureq::get" ascii
    $upost = "ureq::post" ascii
    $rget = "reqwest::get" ascii
    $client = "reqwest::Client" ascii
    $atto = "attohttpc::" ascii
    $mini = "minreq::get" ascii
    $isahc = "isahc::" ascii
    $cmd = "Command::new" ascii
  condition:
    (
      for any i in (1 .. #get) : ( $cmd in (@get[i] .. @get[i] + 400) ) or
      for any i in (1 .. #upost) : ( $cmd in (@upost[i] .. @upost[i] + 400) ) or
      for any i in (1 .. #rget) : ( $cmd in (@rget[i] .. @rget[i] + 400) ) or
      for any i in (1 .. #client) : ( $cmd in (@client[i] .. @client[i] + 400) ) or
      for any i in (1 .. #atto) : ( $cmd in (@atto[i] .. @atto[i] + 400) ) or
      for any i in (1 .. #mini) : ( $cmd in (@mini[i] .. @mini[i] + 400) ) or
      for any i in (1 .. #isahc) : ( $cmd in (@isahc[i] .. @isahc[i] + 400) ) or
      for any i in (1 .. #cmd) : (
        $get in (@cmd[i] .. @cmd[i] + 400) or
        $upost in (@cmd[i] .. @cmd[i] + 400) or
        $rget in (@cmd[i] .. @cmd[i] + 400) or
        $client in (@cmd[i] .. @cmd[i] + 400) or
        $atto in (@cmd[i] .. @cmd[i] + 400) or
        $mini in (@cmd[i] .. @cmd[i] + 400) or
        $isahc in (@cmd[i] .. @cmd[i] + 400)
      )
    )
}

rule rs_build_credential
{
  meta:
    tier = "weak"
    scope = "rust_build"
    eco = "crates"
    comments = "skip"
    summary = "build.rs reads a token variable or a credential path, not an ordinary env::var."
  strings:
    $cargo = "CARGO_REGISTRY_TOKEN" ascii
    $github = "GITHUB_TOKEN" ascii
    $gitlab = "GITLAB_TOKEN" ascii
    $npm = "NPM_TOKEN" ascii
    $aws = "AWS_SECRET_ACCESS_KEY" ascii
    $creds = ".cargo/credentials" ascii
    $toml = "credentials.toml" ascii
    $rsa = "id_rsa" ascii
  condition:
    any of them
}

rule rs_exfil_post
{
  meta:
    tier = "weak"
    scope = "rust"
    eco = "crates"
    comments = "skip"
    summary = "Rust source posts over HTTP within 400 bytes of a wallet or private-key marker."
  strings:
    $post = ".post(" ascii
    $upost = "ureq::post" ascii
    $method = "Method::POST" ascii
    $priv = "private_key" ascii
    $secret = "secret_key" ascii
    $mnemonic = "mnemonic" ascii
    $seed = "seed_phrase" ascii
    $wallet = "wallet_key" ascii
  condition:
    (
      for any i in (1 .. #post) : (
        $priv in (@post[i] .. @post[i] + 400) or
        $secret in (@post[i] .. @post[i] + 400) or
        $mnemonic in (@post[i] .. @post[i] + 400) or
        $seed in (@post[i] .. @post[i] + 400) or
        $wallet in (@post[i] .. @post[i] + 400)
      ) or
      for any i in (1 .. #upost) : (
        $priv in (@upost[i] .. @upost[i] + 400) or
        $secret in (@upost[i] .. @upost[i] + 400) or
        $mnemonic in (@upost[i] .. @upost[i] + 400) or
        $seed in (@upost[i] .. @upost[i] + 400) or
        $wallet in (@upost[i] .. @upost[i] + 400)
      ) or
      for any i in (1 .. #method) : (
        $priv in (@method[i] .. @method[i] + 400) or
        $secret in (@method[i] .. @method[i] + 400) or
        $mnemonic in (@method[i] .. @method[i] + 400) or
        $seed in (@method[i] .. @method[i] + 400) or
        $wallet in (@method[i] .. @method[i] + 400)
      ) or
      for any i in (1 .. #priv) : (
        $post in (@priv[i] .. @priv[i] + 400) or
        $upost in (@priv[i] .. @priv[i] + 400) or
        $method in (@priv[i] .. @priv[i] + 400)
      )
    )
}

rule rs_include_bytes_exec
{
  meta:
    tier = "weak"
    scope = "rust"
    eco = "crates"
    comments = "skip"
    summary = "include_bytes! sits within 400 bytes of a process spawn."
  strings:
    $inc = "include_bytes!" ascii
    $cmd = "Command::new" ascii
  condition:
    for any i in (1 .. #inc) : ( $cmd in (@inc[i] .. @inc[i] + 400) ) or
    for any i in (1 .. #cmd) : ( $inc in (@cmd[i] .. @cmd[i] + 400) )
}

rule rs_build_process
{
  meta:
    tier = "info"
    scope = "rust_build"
    eco = "crates"
    comments = "skip"
    summary = "build.rs starts a process. cc and bindgen do this on ordinary releases."
  strings:
    $cmd = "Command::new" ascii
  condition:
    $cmd
}

rule rs_build_network
{
  meta:
    tier = "info"
    scope = "rust_build"
    eco = "crates"
    comments = "skip"
    summary = "build.rs uses an HTTP client."
  strings:
    $get = "ureq::get" ascii
    $upost = "ureq::post" ascii
    $rget = "reqwest::get" ascii
    $client = "reqwest::Client" ascii
    $atto = "attohttpc::" ascii
    $mini = "minreq::get" ascii
    $isahc = "isahc::" ascii
  condition:
    any of them
}

rule rs_include_bytes
{
  meta:
    tier = "info"
    scope = "rust"
    eco = "crates"
    comments = "skip"
    summary = "Rust source adds an include_bytes!."
  strings:
    $inc = "include_bytes!" ascii
  condition:
    $inc
}

rule rs_long_encoded_line
{
  meta:
    tier = "info"
    scope = "rust"
    eco = "crates"
    comments = "skip"
    summary = "A line assigns a base64 literal of 80 or more characters."
  strings:
    $mark = " = \"" ascii
  condition:
    for any i in (1 .. #mark) : (
      @mark[i] + 4 + 79 < filesize and
      for all k in (0 .. 79) : (
        (
          (uint8(@mark[i] + 4 + k) >= 0x41 and uint8(@mark[i] + 4 + k) <= 0x5a) or
          (uint8(@mark[i] + 4 + k) >= 0x61 and uint8(@mark[i] + 4 + k) <= 0x7a) or
          (uint8(@mark[i] + 4 + k) >= 0x30 and uint8(@mark[i] + 4 + k) <= 0x39) or
          uint8(@mark[i] + 4 + k) == 0x2b or
          uint8(@mark[i] + 4 + k) == 0x2f or
          uint8(@mark[i] + 4 + k) == 0x3d
        )
      )
    )
}
