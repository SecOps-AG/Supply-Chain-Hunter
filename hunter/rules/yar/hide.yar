// Concealed code: encoded calls, renamed builtins, and characters a person does not see.

rule js_obfuscator_names
{
  meta:
    tier = "weak"
    scope = "js,bundle"
    eco = "npm"
    newness = "rule"
    summary = "More than twenty identifier names that look like the output of a JavaScript obfuscator."
  strings:
    $tag = /\x5f\x30\x78[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]/
  condition:
    #tag > 20 and
    for any i in (1 .. #tag) : (
      @tag[i] + 6 < filesize and
      uint8(@tag[i]) == 0x5f and
      uint8(@tag[i] + 1) == 0x30 and
      uint8(@tag[i] + 2) == 0x78 and
      uint8(@tag[i] + 3) != 0x00 and
      uint8(@tag[i] + 3) != 0x20 and
      (
        (uint8(@tag[i] + 3) >= 0x30 and uint8(@tag[i] + 3) <= 0x39) or
        (uint8(@tag[i] + 3) >= 0x41 and uint8(@tag[i] + 3) <= 0x46) or
        (uint8(@tag[i] + 3) >= 0x61 and uint8(@tag[i] + 3) <= 0x66)
      ) and
      (
        (uint8(@tag[i] + 4) >= 0x30 and uint8(@tag[i] + 4) <= 0x39) or
        (uint8(@tag[i] + 4) >= 0x41 and uint8(@tag[i] + 4) <= 0x46) or
        (uint8(@tag[i] + 4) >= 0x61 and uint8(@tag[i] + 4) <= 0x66)
      )
    )
}

rule js_dynamic_eval
{
  meta:
    tier = "weak"
    scope = "js,bundle"
    eco = "npm"
    summary = "eval or Function is fed decoded text, or a packed function is passed to eval."
  strings:
    $eval_atob = "eval(atob(" ascii
    $eval_atob_sp = "eval( atob(" ascii
    $fn_atob = "Function(atob(" ascii
    $fn_atob_sp = "Function( atob(" ascii
    $packer = "eval(function(p,a,c,k,e" ascii
    $evfn = "eval(function(" ascii
    $eval = "\x65val(" ascii
    $newfn = "\x6eew Function" ascii
    $fcc = "\x66romCharCode" ascii
  condition:
    $eval_atob or
    $eval_atob_sp or
    $fn_atob or
    $fn_atob_sp or
    $packer or
    $evfn or
    (
      for any i in (1 .. #eval) : (
        $fcc in (@eval[i] .. @eval[i] + 170)
      )
    ) or (
      for any i in (1 .. #newfn) : (
        $fcc in (@newfn[i] .. @newfn[i] + 180)
      )
    ) or (
      for any i in (1 .. #fcc) : (
        $eval in (@fcc[i] .. @fcc[i] + 170) or
        $newfn in (@fcc[i] .. @fcc[i] + 180)
      )
    )
}

rule eval_fromcharcode_direct
{
  meta:
    tier = "weak"
    scope = "js,bundle"
    eco = "npm"
    summary = "eval is called on a character-code string written out in place."
  strings:
    $direct = "eval(String.fromCharCode" ascii
    $spaced = "eval( String.fromCharCode" ascii
  condition:
    for any i in (1 .. #direct) : (
      @direct[i] < filesize and
      @direct[i] >= 0 and
      uint8(@direct[i]) >= 0x09 and
      uint8(@direct[i]) <= 0x7e and
      uint8(@direct[i]) != 0x00 and
      uint8(@direct[i]) != 0x01 and
      uint8(@direct[i]) != 0x02 and
      uint8(@direct[i]) != 0x7f and
      not (@direct[i] > filesize)
    ) or
    for any i in (1 .. #spaced) : (
      @spaced[i] < filesize and
      @spaced[i] >= 0 and
      uint8(@spaced[i]) >= 0x09 and
      uint8(@spaced[i]) <= 0x7e and
      uint8(@spaced[i]) != 0x00 and
      uint8(@spaced[i]) != 0x01 and
      uint8(@spaced[i]) != 0x02 and
      uint8(@spaced[i]) != 0x7f and
      not (@spaced[i] > filesize)
    )
}

rule js_global_require_alias
{
  meta:
    tier = "weak"
    scope = "js,bundle"
    eco = "npm"
    summary = "require is stored on a short global property."
  strings:
    $g1 = "global['" ascii
    $g2 = "global[\"" ascii
    $tail = "] = require" ascii
    $tight = "]=require" ascii
  condition:
    (
      for any i in (1 .. #g1) : (
        @g1[i] + 6 < filesize and
        uint8(@g1[i]) == 0x67 and
        uint8(@g1[i] + 1) == 0x6c and
        (
          $tail in (@g1[i] .. @g1[i] + 28) or
          $tight in (@g1[i] .. @g1[i] + 22)
        )
      )
    ) or (
      for any i in (1 .. #g2) : (
        @g2[i] + 6 < filesize and
        uint8(@g2[i]) == 0x67 and
        uint8(@g2[i] + 1) == 0x6c and
        (
          $tail in (@g2[i] .. @g2[i] + 28) or
          $tight in (@g2[i] .. @g2[i] + 22)
        )
      )
    )
}

rule obf_getattr_exec
{
  meta:
    tier = "weak"
    scope = "code"
    eco = "both"
    summary = "exec, eval, import, or system is reached through getattr and then called."
  strings:
    $call = "getattr(" ascii
    $bi = "__builtins__" ascii
    $exec = "'exec'" ascii
    $exec2 = "\"exec\"" ascii
    $eval = "'eval'" ascii
    $eval2 = "\"eval\"" ascii
    $imp = "'__import__'" ascii
    $imp2 = "\"__import__\"" ascii
    $sys = "'system'" ascii
    $sys2 = "\"system\"" ascii
    $invoke = ")(" ascii
  condition:
    (
      for any i in (1 .. #call) : (
        $bi in (@call[i] .. @call[i] + 18)
      )
    ) or (
      for any i in (1 .. #call) : (
        (
          $exec in (@call[i] .. @call[i] + 80) or
          $exec2 in (@call[i] .. @call[i] + 80) or
          $eval in (@call[i] .. @call[i] + 80) or
          $eval2 in (@call[i] .. @call[i] + 80) or
          $imp in (@call[i] .. @call[i] + 80) or
          $imp2 in (@call[i] .. @call[i] + 80) or
          $sys in (@call[i] .. @call[i] + 80) or
          $sys2 in (@call[i] .. @call[i] + 80)
        ) and
        $invoke in (@call[i] .. @call[i] + 96)
      )
    )
}

rule obf_escape_runs
{
  meta:
    tier = "weak"
    scope = "code,bundle"
    eco = "both"
    summary = "A long run of hex escapes, a JSFuck fragment repeated many times, or a long character-code list."
  strings:
    $hex = /(\x5c\x78[0-9a-fA-F][0-9a-fA-F]){50}/
    $js = "[+!+[]]" ascii
    $fcc = /\x66\x72\x6f\x6d\x43\x68\x61\x72\x43\x6f\x64\x65\s{0,4}\(\s{0,4}(\d{1,3}\s{0,4},\s{0,4}){9}\d{1,3}/
  condition:
    (
      for any i in (1 .. #hex) : (
        @hex[i] < filesize and
        uint8(@hex[i]) == 0x5c and
        uint8(@hex[i] + 1) == 0x78 and
        @hex[i] + 2 < filesize
      )
    ) or (
      #js > 10 and
      for any i in (1 .. #js) : (
        @js[i] < filesize and
        uint8(@js[i]) == 0x5b and
        uint8(@js[i] + 1) == 0x2b
      )
    ) or (
      for any i in (1 .. #fcc) : (
        @fcc[i] < filesize and
        uint8(@fcc[i]) == 0x66 and
        uint8(@fcc[i] + 1) == 0x72 and
        uint8(@fcc[i] + 2) == 0x6f and
        uint8(@fcc[i] + 3) == 0x6d
      )
    )
}

rule obf_log_suppress
{
  meta:
    tier = "weak"
    scope = "js"
    eco = "npm"
    summary = "Console methods are replaced with an empty function next to encoded text."
  strings:
    $log = "console.log" ascii
    $warn = "console.warn" ascii
    $err = "console.error" ascii
    $info = "console.info" ascii
    $dbg = "console.debug" ascii
    $fn = "function ()" ascii
    $fn2 = "function()" ascii
    $arrow = "() =>" ascii
    $arrow2 = "()=>" ascii
    $fcc = "\x66romCharCode" ascii
    $hex = /["']\x5cx[0-9a-fA-F]{2}\x5cx[0-9a-fA-F]{2}/
  condition:
    (
      for any i in (1 .. #log) : (
        $fn in (@log[i] .. @log[i] + 40) or
        $fn2 in (@log[i] .. @log[i] + 40) or
        $arrow in (@log[i] .. @log[i] + 40) or
        $arrow2 in (@log[i] .. @log[i] + 40)
      ) or
      for any i in (1 .. #warn) : (
        $fn in (@warn[i] .. @warn[i] + 40) or
        $fn2 in (@warn[i] .. @warn[i] + 40) or
        $arrow in (@warn[i] .. @warn[i] + 40)
      ) or
      for any i in (1 .. #err) : (
        $fn in (@err[i] .. @err[i] + 40) or
        $arrow in (@err[i] .. @err[i] + 40)
      ) or
      for any i in (1 .. #info) : (
        $fn in (@info[i] .. @info[i] + 40) or
        $arrow in (@info[i] .. @info[i] + 40)
      ) or
      for any i in (1 .. #dbg) : (
        $fn in (@dbg[i] .. @dbg[i] + 40) or
        $arrow in (@dbg[i] .. @dbg[i] + 40)
      )
    ) and (
      $fcc or $hex
    )
}

rule obf_pyarmor
{
  meta:
    tier = "weak"
    scope = "py"
    eco = "pypi"
    summary = "A Python file protected by a commercial bytecode wrapper."
  strings:
    $a = "__pyarmor__(" ascii
    $b = "pyarmor_runtime" ascii
    $c = "__\x61rmor_enter__" ascii
  condition:
    for any i in (1 .. #a) : (
      @a[i] < filesize and
      @a[i] >= 0 and
      uint8(@a[i]) >= 0x09 and
      uint8(@a[i]) <= 0x7e and
      uint8(@a[i]) != 0x00 and
      uint8(@a[i]) != 0x01 and
      uint8(@a[i]) != 0x02 and
      uint8(@a[i]) != 0x7f and
      not (@a[i] > filesize)
    ) or
    for any i in (1 .. #b) : (
      @b[i] < filesize and
      @b[i] >= 0 and
      uint8(@b[i]) >= 0x09 and
      uint8(@b[i]) <= 0x7e and
      uint8(@b[i]) != 0x00 and
      uint8(@b[i]) != 0x01 and
      uint8(@b[i]) != 0x02 and
      uint8(@b[i]) != 0x7f and
      not (@b[i] > filesize)
    ) or
    for any i in (1 .. #c) : (
      @c[i] < filesize and
      @c[i] >= 0 and
      uint8(@c[i]) >= 0x09 and
      uint8(@c[i]) <= 0x7e and
      uint8(@c[i]) != 0x00 and
      uint8(@c[i]) != 0x01 and
      uint8(@c[i]) != 0x02 and
      uint8(@c[i]) != 0x7f and
      not (@c[i] > filesize)
    )
}

rule obf_split_module_name
{
  meta:
    tier = "weak"
    scope = "code"
    eco = "both"
    summary = "A sensitive module or function name is built by joining string pieces."
  strings:
    $c1 = "'child_'" ascii
    $c2 = "\"child_\"" ascii
    $c3 = "'chil'" ascii
    $c4 = "'chi'" ascii
    $p1 = "'process'" ascii
    $p2 = "'_process'" ascii
    $p3 = "'d_process'" ascii
    $p4 = "'ld_process'" ascii
    $e1 = "'ev'" ascii
    $e2 = "'e'" ascii
    $a1 = "'al'" ascii
    $a2 = "'val'" ascii
    $s1 = "'sub'" ascii
    $s2 = "'subpro'" ascii
    $s3 = "'cess'" ascii
    $imp = "\x5f_import__(" ascii
    $join = "' + '" ascii
    $joind = "\" + \"" ascii
  condition:
    (
      ($c1 or $c2 or $c3 or $c4) and ($p1 or $p2 or $p3 or $p4) and ($join or $joind)
    ) or (
      ($e1 or $e2) and ($a1 or $a2) and ($join or $joind)
    ) or (
      ($s1 or $s2) and ($p1 or $s3) and ($join or $joind)
    ) or (
      for any i in (1 .. #imp) : (
        $join in (@imp[i] .. @imp[i] + 36) or
        $joind in (@imp[i] .. @imp[i] + 36)
      )
    )
}

rule hex_buffer_exec
{
  meta:
    tier = "weak"
    scope = "code,bundle"
    eco = "both"
    summary = "Hex-decoded bytes are passed to eval, exec, Function, or require."
  strings:
    $buf = "Buffer.from" ascii
    $hex = "'hex'" ascii
    $hex2 = "\"hex\"" ascii
    $eval = "\x65val(" ascii
    $fn = "\x46unction" ascii
    $req = "require(" ascii
    $exec = "exec(" ascii
    $fromhex = "bytes.fromhex" ascii
    $unhex = "binascii.unhexlify" ascii
  condition:
    (
      for any i in (1 .. #buf) : (
        ($hex in (@buf[i] .. @buf[i] + 80) or $hex2 in (@buf[i] .. @buf[i] + 80)) and
        (
          $eval in (@buf[i] .. @buf[i] + 280) or
          $fn in (@buf[i] .. @buf[i] + 280) or
          $req in (@buf[i] .. @buf[i] + 280) or
          $exec in (@buf[i] .. @buf[i] + 280)
        )
      )
    ) or (
      for any i in (1 .. #exec) : (
        $fromhex in (@exec[i] .. @exec[i] + 140) or
        $unhex in (@exec[i] .. @exec[i] + 140)
      )
    ) or (
      for any i in (1 .. #eval) : (
        $fromhex in (@eval[i] .. @eval[i] + 140) or
        $unhex in (@eval[i] .. @eval[i] + 140)
      )
    )
}

rule vm_run_decoded
{
  meta:
    tier = "weak"
    scope = "js,bundle"
    eco = "npm"
    summary = "The vm module runs text that was just decoded."
  strings:
    $a = "\x72unInThisContext" ascii
    $b = "\x72unInNewContext" ascii
    $c = "compileFunction" ascii
    $atob = "atob" ascii
    $b64 = "\x62ase64" ascii
    $fcc = "\x66romCharCode" ascii
    $hex = "'hex'" ascii
    $hex2 = "\"hex\"" ascii
  condition:
    (
      for any i in (1 .. #a) : (
        $atob in (@a[i] .. @a[i] + 130) or
        $b64 in (@a[i] .. @a[i] + 130) or
        $fcc in (@a[i] .. @a[i] + 130) or
        $hex in (@a[i] .. @a[i] + 130) or
        $hex2 in (@a[i] .. @a[i] + 130)
      )
    ) or (
      for any i in (1 .. #b) : (
        $atob in (@b[i] .. @b[i] + 130) or
        $b64 in (@b[i] .. @b[i] + 130) or
        $fcc in (@b[i] .. @b[i] + 130)
      )
    ) or (
      for any i in (1 .. #c) : (
        $atob in (@c[i] .. @c[i] + 130) or
        $b64 in (@c[i] .. @c[i] + 130) or
        $fcc in (@c[i] .. @c[i] + 130)
      )
    )
}

rule hidden_bidi
{
  meta:
    tier = "weak"
    scope = "code"
    eco = "both"
    summary = "Bidirectional control characters that can display source in a different order than it runs."
  strings:
    $rlo = { E2 80 AE }
    $lro = { E2 80 AD }
    $rle = { E2 80 AB }
    $lre = { E2 80 AA }
    $pdf = { E2 80 AC }
    $lri = { E2 81 A6 }
    $rli = { E2 81 A7 }
    $fsi = { E2 81 A8 }
    $pdi = { E2 81 A9 }
  condition:
    for any i in (1 .. #rlo) : (@rlo[i] < filesize) or
    for any i in (1 .. #lro) : (@lro[i] < filesize) or
    for any i in (1 .. #rle) : (@rle[i] < filesize) or
    for any i in (1 .. #lre) : (@lre[i] < filesize) or
    for any i in (1 .. #pdf) : (@pdf[i] < filesize) or
    for any i in (1 .. #lri) : (@lri[i] < filesize) or
    for any i in (1 .. #rli) : (@rli[i] < filesize) or
    for any i in (1 .. #fsi) : (@fsi[i] < filesize) or
    for any i in (1 .. #pdi) : (@pdi[i] < filesize)
}

rule hidden_zero_width
{
  meta:
    tier = "weak"
    scope = "code"
    eco = "both"
    summary = "A zero-width character glued to an identifier."
  strings:
    $z1 = { E2 80 8B }
    $z2 = { E2 80 8C }
    $z3 = { E2 80 8D }
  condition:
    for any i in (1 .. #z1) : (
      (
        @z1[i] > 0 and
        (
        (uint8(@z1[i] - 1) >= 0x30 and uint8(@z1[i] - 1) <= 0x39) or
        (uint8(@z1[i] - 1) >= 0x41 and uint8(@z1[i] - 1) <= 0x5a) or
        (uint8(@z1[i] - 1) >= 0x61 and uint8(@z1[i] - 1) <= 0x7a) or
        uint8(@z1[i] - 1) == 0x5f or
        uint8(@z1[i] - 1) == 0x24
      )
      ) or (
        @z1[i] + 3 < filesize and
        (
        (uint8(@z1[i] + 3) >= 0x30 and uint8(@z1[i] + 3) <= 0x39) or
        (uint8(@z1[i] + 3) >= 0x41 and uint8(@z1[i] + 3) <= 0x5a) or
        (uint8(@z1[i] + 3) >= 0x61 and uint8(@z1[i] + 3) <= 0x7a) or
        uint8(@z1[i] + 3) == 0x5f or
        uint8(@z1[i] + 3) == 0x24
      )
      )
    ) or
    for any i in (1 .. #z2) : (
      (
        @z2[i] > 0 and
        (
        (uint8(@z2[i] - 1) >= 0x30 and uint8(@z2[i] - 1) <= 0x39) or
        (uint8(@z2[i] - 1) >= 0x41 and uint8(@z2[i] - 1) <= 0x5a) or
        (uint8(@z2[i] - 1) >= 0x61 and uint8(@z2[i] - 1) <= 0x7a) or
        uint8(@z2[i] - 1) == 0x5f or
        uint8(@z2[i] - 1) == 0x24
      )
      ) or (
        @z2[i] + 3 < filesize and
        (
        (uint8(@z2[i] + 3) >= 0x30 and uint8(@z2[i] + 3) <= 0x39) or
        (uint8(@z2[i] + 3) >= 0x41 and uint8(@z2[i] + 3) <= 0x5a) or
        (uint8(@z2[i] + 3) >= 0x61 and uint8(@z2[i] + 3) <= 0x7a) or
        uint8(@z2[i] + 3) == 0x5f or
        uint8(@z2[i] + 3) == 0x24
      )
      )
    ) or
    for any i in (1 .. #z3) : (
      (
        @z3[i] > 0 and
        (
        (uint8(@z3[i] - 1) >= 0x30 and uint8(@z3[i] - 1) <= 0x39) or
        (uint8(@z3[i] - 1) >= 0x41 and uint8(@z3[i] - 1) <= 0x5a) or
        (uint8(@z3[i] - 1) >= 0x61 and uint8(@z3[i] - 1) <= 0x7a) or
        uint8(@z3[i] - 1) == 0x5f or
        uint8(@z3[i] - 1) == 0x24
      )
      ) or (
        @z3[i] + 3 < filesize and
        (
        (uint8(@z3[i] + 3) >= 0x30 and uint8(@z3[i] + 3) <= 0x39) or
        (uint8(@z3[i] + 3) >= 0x41 and uint8(@z3[i] + 3) <= 0x5a) or
        (uint8(@z3[i] + 3) >= 0x61 and uint8(@z3[i] + 3) <= 0x7a) or
        uint8(@z3[i] + 3) == 0x5f or
        uint8(@z3[i] + 3) == 0x24
      )
      )
    )
}

rule hidden_unicode_tag
{
  meta:
    tier = "weak"
    scope = "code,docs"
    eco = "both"
    summary = "A run of Unicode tag characters, which can hide a second string inside visible text."
  strings:
    $tag = { F3 A0 ( 80 | 81 ) ?? F3 A0 ( 80 | 81 ) ?? F3 A0 ( 80 | 81 ) ?? }
  condition:
    for any i in (1 .. #tag) : (
      @tag[i] + 11 < filesize and
      uint8(@tag[i]) == 0xf3 and
      uint8(@tag[i] + 1) == 0xa0 and
      (uint8(@tag[i] + 2) == 0x80 or uint8(@tag[i] + 2) == 0x81) and
      uint8(@tag[i] + 4) == 0xf3 and
      uint8(@tag[i] + 5) == 0xa0 and
      uint8(@tag[i] + 8) == 0xf3 and
      uint8(@tag[i] + 9) == 0xa0
    )
}

rule ai_reviewer_injection
{
  meta:
    tier = "weak"
    scope = "code,docs"
    eco = "both"
    summary = "Text that tells a reviewer to ignore earlier findings or to call the package safe."
  strings:
    $ign = "\x69gnore" nocase ascii
    $dis = "disregard" nocase ascii
    $prev = "previous" nocase ascii
    $prior = "prior" nocase ascii
    $above = "above" nocase ascii
    $inst = "instructions" nocase ascii
    $find = "findings" nocase ascii
    $rules = "rules" nocase ascii
    $mark = "mark this" nocase ascii
    $report = "report this" nocase ascii
    $class = "classify this" nocase ascii
    $safe = "safe" nocase ascii
    $benign = "\x62enign" nocase ascii
    $clean = "clean" nocase ascii
    $you = "you are" nocase ascii
    $rev = "reviewer" nocase ascii
    $aud = "auditor" nocase ascii
    $scan = "scanner" nocase ascii
  condition:
    (
      for any i in (1 .. #ign) : (
        (
          $prev in (@ign[i] .. @ign[i] + 24) or
          $prior in (@ign[i] .. @ign[i] + 24) or
          $above in (@ign[i] .. @ign[i] + 24)
        ) and (
          $inst in (@ign[i] .. @ign[i] + 48) or
          $find in (@ign[i] .. @ign[i] + 48) or
          $rules in (@ign[i] .. @ign[i] + 48)
        )
      )
    ) or (
      for any i in (1 .. #dis) : (
        (
          $prev in (@dis[i] .. @dis[i] + 28) or
          $prior in (@dis[i] .. @dis[i] + 28) or
          $above in (@dis[i] .. @dis[i] + 28)
        ) and
        $inst in (@dis[i] .. @dis[i] + 56)
      )
    ) or (
      for any i in (1 .. #mark) : (
        $safe in (@mark[i] .. @mark[i] + 48) or
        $benign in (@mark[i] .. @mark[i] + 48) or
        $clean in (@mark[i] .. @mark[i] + 48)
      )
    ) or (
      for any i in (1 .. #report) : (
        $safe in (@report[i] .. @report[i] + 56) or
        $benign in (@report[i] .. @report[i] + 56) or
        $clean in (@report[i] .. @report[i] + 56)
      )
    ) or (
      for any i in (1 .. #class) : (
        $safe in (@class[i] .. @class[i] + 56) or
        $benign in (@class[i] .. @class[i] + 56) or
        $clean in (@class[i] .. @class[i] + 56)
      )
    ) or (
      for any i in (1 .. #you) : (
        (
          $rev in (@you[i] .. @you[i] + 40) or
          $aud in (@you[i] .. @you[i] + 40) or
          $scan in (@you[i] .. @you[i] + 48)
        ) and (
          $benign in (@you[i] .. @you[i] + 120) or
          $safe in (@you[i] .. @you[i] + 120)
        )
      )
    )
}
