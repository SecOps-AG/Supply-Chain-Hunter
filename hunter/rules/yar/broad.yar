// Broad signals. A hit asks for a full read. It does not set a score floor.

rule h_decode_exec
{
  meta:
    tier = "weak"
    scope = "code,manifest,workflow,bundle"
    eco = "both"
    summary = "A decode step sits next to exec, eval, spawn, or Function."
  strings:
    $b64 = "\x62ase64" nocase ascii
    $atob = "atob" nocase ascii
    $codecs = "codecs.decode" nocase ascii
    // Whole words only, so execute, executor, evaluate and retrieval do not count.
    // execFile, execFileSync, execve, execvp(e), execl(p|e) are exec too.
    $exec = /\b\x65xec(File(Sync)?|ve|vpe?|l[pe]?)?\b/ nocase ascii
    $eval = /\beval\b/ nocase ascii
    $exs = "\x65xecSync" nocase ascii
    $spawn = "spawn" nocase ascii
    // Case-sensitive, so the function keyword and isFunction( do not count.
    $fn = /\bFunction\s*\(/ ascii
  condition:
    (
      for any i in (1 .. #b64) : (
        $exec in (@b64[i] .. @b64[i] + 240) or
        $eval in (@b64[i] .. @b64[i] + 240) or
        $exs in (@b64[i] .. @b64[i] + 240) or
        $spawn in (@b64[i] .. @b64[i] + 240) or
        $fn in (@b64[i] .. @b64[i] + 240) or
        (
          @b64[i] >= 1 and (
            (@b64[i] >= 160 and (
              $exec in (@b64[i] - 160 .. @b64[i]) or
              $eval in (@b64[i] - 160 .. @b64[i]) or
              $exs in (@b64[i] - 160 .. @b64[i])
            )) or (
              @b64[i] < 160 and (
                $exec in (0 .. @b64[i]) or
                $eval in (0 .. @b64[i]) or
                $exs in (0 .. @b64[i])
              )
            )
          )
        )
      )
    ) or (
      for any i in (1 .. #atob) : (
        $exec in (@atob[i] .. @atob[i] + 80) or
        $eval in (@atob[i] - 12 .. @atob[i] + 8) or
        $fn in (@atob[i] - 20 .. @atob[i] + 80) or
        $spawn in (@atob[i] .. @atob[i] + 240) or
        (
          @atob[i] >= 160 and (
            $exec in (@atob[i] - 160 .. @atob[i]) or
            $exs in (@atob[i] - 160 .. @atob[i])
          )
        ) or (
          @atob[i] < 160 and @atob[i] > 0 and (
            $exec in (0 .. @atob[i]) or
            $eval in (0 .. @atob[i])
          )
        )
      )
    ) or (
      for any i in (1 .. #codecs) : (
        $exec in (@codecs[i] .. @codecs[i] + 80) or
        $eval in (@codecs[i] .. @codecs[i] + 80) or
        (
          @codecs[i] >= 160 and $exec in (@codecs[i] - 160 .. @codecs[i])
        )
      )
    )
}

rule h_shell
{
  meta:
    tier = "weak"
    scope = "code,manifest,workflow"
    eco = "both"
    summary = "A child process or a shell is started."
  strings:
    $cp = "\x63hild_process" ascii
    $exs = "\x65xecSync" ascii
    $sps = "\x73pawnSync" ascii
    $sys = "os.system" ascii
    $sub = "subprocess" ascii
    $po = "Popen" ascii
    $cc = "check_call" ascii
    $rt = "Runtime.getRuntime" ascii
    $curl = "curl" ascii
    $pipe = "| sh" ascii
    $pipeb = "| bash" ascii
  condition:
    $cp or $exs or $sps or $sys or $sub or $po or $cc or $rt or
    for any i in (1 .. #curl) : (
      $pipe in (@curl[i] .. @curl[i] + 210) or
      $pipeb in (@curl[i] .. @curl[i] + 210)
    )
}

rule h_credential
{
  meta:
    tier = "weak"
    scope = "code,manifest,workflow"
    eco = "both"
    summary = "A registry token, a cloud key, or an SSH key path is named."
  strings:
    $a = "NPM_TOKEN" nocase ascii
    $b = "NODE_AUTH_TOKEN" nocase ascii
    $c = "AWS_SECRET" nocase ascii
    $d = "AWS_ACCESS_KEY" nocase ascii
    $e = "GH_TOKEN" nocase ascii
    $f = "GITHUB_TOKEN" nocase ascii
    $g = "BROWSER_COOKIE" nocase ascii
    $h = "\x69d_rsa" nocase ascii
    $i = ".ssh\x2f" nocase ascii
    $j = "authorized_keys" nocase ascii
    $k = "credentials.json" nocase ascii
    // A workflow handing the job its own token: secrets.GITHUB_TOKEN, or
    // GITHUB_TOKEN / GH_TOKEN set from it or from github.token.
    $fsec = "secrets.GITHUB_TOKEN" nocase ascii
    $fenv = /\b(GITHUB_TOKEN|GH_TOKEN)\s*:\s*\$\{\{\s*(secrets\.GITHUB_TOKEN|github\.token)\s*\}\}/ nocase ascii
    // The token sent out on the same line as curl or wget is not a plain handoff.
    $fsend = /\b(curl|wget)\b[^\n]{0,200}(secrets\.GITHUB_TOKEN|github\.token|GITHUB_TOKEN|GH_TOKEN)/ nocase ascii
  condition:
    $a or $b or $c or $d or $g or $h or $i or $j or $k or $fsend or
    for any i in (1 .. #e) : (
      not for any j in (1 .. #fenv) : (@fenv[j] == @e[i])
    ) or
    for any i in (1 .. #f) : (
      not $fsec at (@f[i] - 8) and
      not for any j in (1 .. #fenv) : (@fenv[j] == @f[i])
    )
}

rule h_xor
{
  meta:
    tier = "weak"
    scope = "code,bundle"
    eco = "both"
    summary = "Characters are decoded with XOR."
  strings:
    $xor = "xor" nocase ascii
    // xorshift, xoroshiro and xorwow are random number generators, not decoders.
    $prng = /xor(shift|oshiro|wow)/ nocase ascii
    // The XOR is applied to the char code itself. A string hash puts it before.
    // One level of nested parens is allowed: charCodeAt(i % (k.length)) ^ x.
    $ccx = /charCodeAt\(([^()]|\([^()]{0,16}\)){0,24}\)\)?\s*\^/ ascii
    // Reversed order inside a call: push(k ^ s.charCodeAt(i)). A hash puts a
    // closing paren or ^= before it instead.
    $xcc = /[(,]\s*[A-Za-z_$][\w$]{0,40}\s*\^\s*[\w$.\[\]]{1,60}\.charCodeAt\(/ ascii
    $fcc = "\x66romCharCode" ascii
    $op1 = ") ^" ascii
    $op2 = ")^" ascii
    $op3 = ")  ^" ascii
    $op5 = " ^ " ascii
  condition:
    #xor > #prng or
    $ccx or $xcc or
    for any i in (1 .. #fcc) : (
      $op1 in (@fcc[i] .. @fcc[i] + 90) or
      $op2 in (@fcc[i] .. @fcc[i] + 90) or
      $op3 in (@fcc[i] .. @fcc[i] + 90) or
      $op5 in (@fcc[i] .. @fcc[i] + 90)
    )
}

rule h_encoded_import
{
  meta:
    tier = "weak"
    scope = "js,bundle"
    eco = "npm"
    summary = "require or import is given a decoded string."
  strings:
    $req = "require(" ascii
    $imp = "import(" ascii
    $atob = "atob" ascii
    $un = "\x75nescape" ascii
    $dec = "decodeURIComponent" ascii
    $buf = "Buffer.from" ascii
    $b64 = "\x62ase64" ascii
    // A plain module name such as require("base64-js") decodes nothing.
    $reqlit = /require\(\s*["'][A-Za-z0-9@._\/-]{1,80}["']\s*\)/ ascii
    $implit = /import\(\s*["'][A-Za-z0-9@._\/-]{1,80}["']\s*\)/ ascii
  condition:
    (
      for any i in (1 .. #req) : (
        not $reqlit at @req[i] and (
          $atob in (@req[i] .. @req[i] + 24) or
          $un in (@req[i] .. @req[i] + 24) or
          $dec in (@req[i] .. @req[i] + 28) or
          $buf in (@req[i] .. @req[i] + 24) or
          $b64 in (@req[i] .. @req[i] + 40)
        )
      )
    ) or (
      for any i in (1 .. #imp) : (
        not $implit at @imp[i] and (
          $atob in (@imp[i] .. @imp[i] + 24) or
          $un in (@imp[i] .. @imp[i] + 24) or
          $dec in (@imp[i] .. @imp[i] + 28) or
          $buf in (@imp[i] .. @imp[i] + 24) or
          $b64 in (@imp[i] .. @imp[i] + 40)
        )
      )
    )
}

rule h_persistence
{
  meta:
    tier = "weak"
    scope = "code"
    eco = "both"
    comments = "skip"
    summary = "A startup location is named: cron, a shell rc file, a launch agent, systemd, or a Run key."
  strings:
    $a = "crontab" nocase ascii
    $b = "cron.d" nocase ascii
    $c = "\x2fetc\x2frc." nocase ascii
    $d = "\x2fetc\x2finit." nocase ascii
    $e = ".\x62ashrc" nocase ascii
    $f = ".zshrc" nocase ascii
    $g = ".\x62ash_profile" nocase ascii
    $h = "LaunchAgents" nocase ascii
    $i = "LaunchDaemons" nocase ascii
    $j = "schtasks" nocase ascii
    $k = "CurrentVersion" nocase ascii
    $run = "Run" ascii
  condition:
    $a or $b or $c or $d or $e or $f or $g or $h or $i or $j or
    (
      for any i in (1 .. #k) : (
        $run in (@k[i] .. @k[i] + 16)
      )
    )
}
