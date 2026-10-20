// How a package starts another program.

rule exec_download_run
{
  meta:
    tier = "weak"
    scope = "code,manifest,workflow"
    eco = "both"
    summary = "A download client is piped into a shell, a fetch result is passed to eval, or PowerShell downloads a script and runs it."
  strings:
    $curl = "curl" ascii
    $wget = "wget" ascii
    $bash = "| bash" ascii
    $zsh = "| zsh" ascii
    $sh_word = "| sh" ascii
    $sudo = "| sudo" ascii
    $chmod = "chmod" ascii
    $plus = "+x" ascii
    $and = "&&" ascii
    $fetch = "\x66etch(" ascii
    $then = ".then" ascii
    $eval = "eval" ascii
    $iwr = "Invoke-WebRequest" nocase ascii
    $dlf = "DownloadFile" nocase ascii
    $dls = "DownloadString" nocase ascii
    $iex = "Invoke-Expression" nocase ascii
    $iex_short = "iex" nocase ascii
    $start = "Start-Process" nocase ascii
  condition:
    (
      for any i in (1 .. #curl) : (
        $bash in (@curl[i] .. @curl[i] + 220) or
        $zsh in (@curl[i] .. @curl[i] + 220) or
        $sh_word in (@curl[i] .. @curl[i] + 220) or
        $sudo in (@curl[i] .. @curl[i] + 220)
      )
    ) or (
      for any i in (1 .. #wget) : (
        $bash in (@wget[i] .. @wget[i] + 220) or
        $zsh in (@wget[i] .. @wget[i] + 220) or
        $sh_word in (@wget[i] .. @wget[i] + 220) or
        $sudo in (@wget[i] .. @wget[i] + 220)
      )
    ) or (
      for any i in (1 .. #curl) : (
        $and in (@curl[i] .. @curl[i] + 240) and
        $chmod in (@curl[i] .. @curl[i] + 260)
      )
    ) or (
      for any i in (1 .. #wget) : (
        $and in (@wget[i] .. @wget[i] + 210) and
        $chmod in (@wget[i] .. @wget[i] + 230) and
        $plus in (@wget[i] .. @wget[i] + 250)
      )
    ) or (
      for any i in (1 .. #then) : (
        $eval in (@then[i] .. @then[i] + 12)
      )
    ) or (
      for any i in (1 .. #fetch) : (
        $then in (@fetch[i] .. @fetch[i] + 200) and
        $eval in (@fetch[i] .. @fetch[i] + 320)
      )
    ) or (
      for any i in (1 .. #iwr) : (
        $iex in (@iwr[i] .. @iwr[i] + 200) or
        $iex_short in (@iwr[i] .. @iwr[i] + 200) or
        $start in (@iwr[i] .. @iwr[i] + 200)
      )
    ) or (
      for any i in (1 .. #dlf) : (
        $iex in (@dlf[i] .. @dlf[i] + 200) or
        $iex_short in (@dlf[i] .. @dlf[i] + 200) or
        $start in (@dlf[i] .. @dlf[i] + 200)
      )
    ) or (
      for any i in (1 .. #dls) : (
        $iex in (@dls[i] .. @dls[i] + 200) or
        $iex_short in (@dls[i] .. @dls[i] + 200) or
        $start in (@dls[i] .. @dls[i] + 200)
      )
    )
}

rule exec_powershell_enc
{
  meta:
    tier = "weak"
    scope = "code,manifest"
    eco = "both"
    summary = "PowerShell is started with a long encoded command, or an in-memory download is passed to IEX."
  strings:
    $ps = "powershell" nocase ascii
    $full = "-encodedcommand" nocase ascii
    $enc = "-enc" nocase ascii
    $ec = "-ec" nocase ascii
    $short = "-e" nocase ascii
    $iex = "IEX" nocase ascii
    $made = "New-Object" nocase ascii
    $client = "WebClient" nocase ascii
  condition:
    (
      for any i in (1 .. #full) : (
        $ps in (@full[i] - 48 .. @full[i] + 12) and
        @full[i] + 15 + 4 + 39 < filesize and
        for any skip in (1 .. 4) : (
          for all s in (0 .. skip - 1) : (
            uint8(@full[i] + 15 + s) == 0x20 or
            uint8(@full[i] + 15 + s) == 0x09
          ) and
          for all k in (0 .. 39) : (
            (uint8(@full[i] + 15 + skip + k) >= 0x41 and uint8(@full[i] + 15 + skip + k) <= 0x5a) or
            (uint8(@full[i] + 15 + skip + k) >= 0x61 and uint8(@full[i] + 15 + skip + k) <= 0x7a) or
            (uint8(@full[i] + 15 + skip + k) >= 0x30 and uint8(@full[i] + 15 + skip + k) <= 0x39) or
            uint8(@full[i] + 15 + skip + k) == 0x2b or
            uint8(@full[i] + 15 + skip + k) == 0x2f or
            uint8(@full[i] + 15 + skip + k) == 0x3d
          )
        )
      ) or
      for any i in (1 .. #enc) : (
        $ps in (@enc[i] - 48 .. @enc[i] + 12) and
        @enc[i] + 4 + 4 + 39 < filesize and
        for any skip in (1 .. 4) : (
          for all s in (0 .. skip - 1) : (
            uint8(@enc[i] + 4 + s) == 0x20 or
            uint8(@enc[i] + 4 + s) == 0x09
          ) and
          for all k in (0 .. 39) : (
            (uint8(@enc[i] + 4 + skip + k) >= 0x41 and uint8(@enc[i] + 4 + skip + k) <= 0x5a) or
            (uint8(@enc[i] + 4 + skip + k) >= 0x61 and uint8(@enc[i] + 4 + skip + k) <= 0x7a) or
            (uint8(@enc[i] + 4 + skip + k) >= 0x30 and uint8(@enc[i] + 4 + skip + k) <= 0x39) or
            uint8(@enc[i] + 4 + skip + k) == 0x2b or
            uint8(@enc[i] + 4 + skip + k) == 0x2f or
            uint8(@enc[i] + 4 + skip + k) == 0x3d
          )
        )
      ) or
      for any i in (1 .. #ec) : (
        $ps in (@ec[i] - 48 .. @ec[i] + 12) and
        @ec[i] + 3 + 4 + 39 < filesize and
        for any skip in (1 .. 4) : (
          for all s in (0 .. skip - 1) : (
            uint8(@ec[i] + 3 + s) == 0x20 or
            uint8(@ec[i] + 3 + s) == 0x09
          ) and
          for all k in (0 .. 39) : (
            (uint8(@ec[i] + 3 + skip + k) >= 0x41 and uint8(@ec[i] + 3 + skip + k) <= 0x5a) or
            (uint8(@ec[i] + 3 + skip + k) >= 0x61 and uint8(@ec[i] + 3 + skip + k) <= 0x7a) or
            (uint8(@ec[i] + 3 + skip + k) >= 0x30 and uint8(@ec[i] + 3 + skip + k) <= 0x39) or
            uint8(@ec[i] + 3 + skip + k) == 0x2b or
            uint8(@ec[i] + 3 + skip + k) == 0x2f or
            uint8(@ec[i] + 3 + skip + k) == 0x3d
          )
        )
      ) or
      for any i in (1 .. #short) : (
        $ps in (@short[i] - 48 .. @short[i] + 12) and
        @short[i] + 2 + 4 + 39 < filesize and
        for any skip in (1 .. 4) : (
          for all s in (0 .. skip - 1) : (
            uint8(@short[i] + 2 + s) == 0x20 or
            uint8(@short[i] + 2 + s) == 0x09
          ) and
          for all k in (0 .. 39) : (
            (uint8(@short[i] + 2 + skip + k) >= 0x41 and uint8(@short[i] + 2 + skip + k) <= 0x5a) or
            (uint8(@short[i] + 2 + skip + k) >= 0x61 and uint8(@short[i] + 2 + skip + k) <= 0x7a) or
            (uint8(@short[i] + 2 + skip + k) >= 0x30 and uint8(@short[i] + 2 + skip + k) <= 0x39) or
            uint8(@short[i] + 2 + skip + k) == 0x2b or
            uint8(@short[i] + 2 + skip + k) == 0x2f or
            uint8(@short[i] + 2 + skip + k) == 0x3d
          )
        )
      )
    ) or (
      for any i in (1 .. #iex) : (
        $made in (@iex[i] .. @iex[i] + 48) and
        $client in (@iex[i] .. @iex[i] + 80)
      )
    )
}

rule exec_spawn_silent
{
  meta:
    tier = "weak"
    scope = "code"
    eco = "both"
    summary = "A child process is detached with its output discarded, or both Python output streams are sent to DEVNULL."
  strings:
    $det = "detached" ascii
    $yes = "true" ascii
    $stdio = "stdio" ascii
    $drop = "\x69gnore" ascii
    $hide = "windowsHide" ascii
    $out = "stdout" ascii
    $err = "stderr" ascii
    $dev = "DEVNULL" ascii
  condition:
    (
      for any i in (1 .. #det) : (
        $yes in (@det[i] .. @det[i] + 14) and
        (
          (
            $stdio in (@det[i] .. @det[i] + 90) and
            $drop in (@det[i] .. @det[i] + 110)
          ) or (
            $hide in (@det[i] .. @det[i] + 90) and
            $yes in (@det[i] .. @det[i] + 110)
          )
        )
      )
    ) or (
      for any i in (1 .. #out) : (
        $dev in (@out[i] .. @out[i] + 36) and
        $err in (@out[i] .. @out[i] + 170) and
        $dev in (@out[i] + 8 .. @out[i] + 190)
      )
    )
}

rule exec_node_e
{
  meta:
    tier = "weak"
    scope = "js,npm_manifest,shell"
    eco = "npm"
    summary = "Node is asked to run a one-line script with -e or -p."
  strings:
    $dash_e = "\x6eode -e" ascii
    $dash_p = "\x6eode -p" ascii
    $qnode = "'node'" ascii
    $dnode = "\"node\"" ascii
    $btnode = "`node`" ascii
    $qe = "'-e'" ascii
    $qp = "'-p'" ascii
    $de = "\"-e\"" ascii
    $dp = "\"-p\"" ascii
    $spawn = "spawn" ascii
    $exec = "\x65xec" ascii
    $fork = "fork(" ascii
  condition:
    $dash_e or
    $dash_p or
    (
      for any i in (1 .. #qnode) : (
        (
          $qe in (@qnode[i] .. @qnode[i] + 16) or
          $qp in (@qnode[i] .. @qnode[i] + 16) or
          $de in (@qnode[i] .. @qnode[i] + 16) or
          $dp in (@qnode[i] .. @qnode[i] + 16)
        ) and (
          $spawn in (@qnode[i] - 70 .. @qnode[i]) or
          $exec in (@qnode[i] - 70 .. @qnode[i]) or
          $fork in (@qnode[i] - 70 .. @qnode[i]) or
          @qnode[i] < 70
        )
      )
    ) or (
      for any i in (1 .. #dnode) : (
        (
          $qe in (@dnode[i] .. @dnode[i] + 16) or
          $qp in (@dnode[i] .. @dnode[i] + 16) or
          $de in (@dnode[i] .. @dnode[i] + 16) or
          $dp in (@dnode[i] .. @dnode[i] + 16)
        )
      )
    ) or (
      for any i in (1 .. #btnode) : (
        $qe in (@btnode[i] .. @btnode[i] + 16) or
        $qp in (@btnode[i] .. @btnode[i] + 16)
      )
    )
}

rule exec_whoami
{
  meta:
    tier = "info"
    scope = "code"
    eco = "both"
    summary = "A shell helper asks the operating system for the current user or the machine name."
  strings:
    $who = "whoami" ascii
    $hostn = "\x68ostname" ascii
    $ck = "check_output" ascii
    $exs = "\x65xecSync" ascii
    $ex = "exec(" ascii
    $sp = "spawn(" ascii
    $sys = "\x73ystem(" ascii
    $pop = "popen(" ascii
    $run = "run(" ascii
  condition:
    (
      for any i in (1 .. #who) : (
        (@who[i] >= 50 and (
          $ck in (@who[i] - 50 .. @who[i]) or
          $exs in (@who[i] - 50 .. @who[i]) or
          $ex in (@who[i] - 50 .. @who[i]) or
          $sp in (@who[i] - 50 .. @who[i]) or
          $sys in (@who[i] - 50 .. @who[i]) or
          $pop in (@who[i] - 50 .. @who[i]) or
          $run in (@who[i] - 50 .. @who[i])
        )) or (
          @who[i] < 50 and (
            $ck in (0 .. @who[i]) or
            $exs in (0 .. @who[i]) or
            $ex in (0 .. @who[i]) or
            $sp in (0 .. @who[i]) or
            $sys in (0 .. @who[i]) or
            $pop in (0 .. @who[i]) or
            $run in (0 .. @who[i])
          )
        )
      )
    ) or (
      for any i in (1 .. #hostn) : (
        (@hostn[i] >= 50 and (
          $ck in (@hostn[i] - 50 .. @hostn[i]) or
          $exs in (@hostn[i] - 50 .. @hostn[i]) or
          $ex in (@hostn[i] - 50 .. @hostn[i]) or
          $sp in (@hostn[i] - 50 .. @hostn[i]) or
          $sys in (@hostn[i] - 50 .. @hostn[i]) or
          $pop in (@hostn[i] - 50 .. @hostn[i]) or
          $run in (@hostn[i] - 50 .. @hostn[i])
        )) or (
          @hostn[i] < 50 and (
            $ck in (0 .. @hostn[i]) or
            $ex in (0 .. @hostn[i]) or
            $sp in (0 .. @hostn[i]) or
            $sys in (0 .. @hostn[i]) or
            $pop in (0 .. @hostn[i]) or
            $run in (0 .. @hostn[i])
          )
        )
      )
    )
}

rule net_reverse_shell
{
  meta:
    tier = "weak"
    scope = "code,manifest"
    eco = "both"
    summary = "An interactive shell is wired to a network socket, or a pty is handed a shell binary."
  strings:
    $bash = "bash -i" ascii
    $tcp = "\x2fdev\x2ftcp\x2f" ascii
    $udp = "\x2fdev\x2fudp\x2f" ascii
    $nc = "nc " ascii
    $ncat = "ncat " ascii
    $netcat = "netcat " ascii
    $flag = "-e " ascii
    $binsh = "\x2fbin\x2fsh" ascii
    $binbash = "\x2fbin\x2fbash" ascii
    $pty = "pty.spawn" ascii
    $dup = "os.dup2" ascii
    $fileno = "fileno()" ascii
  condition:
    (
      for any i in (1 .. #bash) : (
        $tcp in (@bash[i] .. @bash[i] + 48) or
        $udp in (@bash[i] .. @bash[i] + 48)
      )
    ) or (
      for any i in (1 .. #nc) : (
        $flag in (@nc[i] .. @nc[i] + 40) and
        ($binsh in (@nc[i] .. @nc[i] + 56) or $binbash in (@nc[i] .. @nc[i] + 56))
      )
    ) or (
      for any i in (1 .. #ncat) : (
        $flag in (@ncat[i] .. @ncat[i] + 40) and
        ($binsh in (@ncat[i] .. @ncat[i] + 56) or $binbash in (@ncat[i] .. @ncat[i] + 56))
      )
    ) or (
      for any i in (1 .. #netcat) : (
        $flag in (@netcat[i] .. @netcat[i] + 40) and
        ($binsh in (@netcat[i] .. @netcat[i] + 64) or $binbash in (@netcat[i] .. @netcat[i] + 64))
      )
    ) or (
      for any i in (1 .. #pty) : (
        $binsh in (@pty[i] .. @pty[i] + 28) or
        $binbash in (@pty[i] .. @pty[i] + 28)
      )
    ) or (
      for any i in (1 .. #dup) : (
        $fileno in (@dup[i] .. @dup[i] + 36)
      )
    )
}

rule proc_dll_inject
{
  meta:
    tier = "weak"
    scope = "code"
    eco = "both"
    summary = "Two Windows calls used together to write into another process and start a thread there."
  strings:
    $w1 = "WriteP" ascii
    $w2 = "rocessMemory" ascii
    $c1 = "CreateR" ascii
    $c2 = "emoteThread" ascii
    $v1 = "VirtualA" ascii
    $v2 = "llocEx" ascii
    $n1 = "NtCreateT" ascii
    $n2 = "hreadEx" ascii
  condition:
    (
      (for any i in (1 .. #w1) : ($w2 at @w1[i] + 6)) and
      (for any i in (1 .. #c1) : ($c2 at @c1[i] + 7))
    ) or (
      (for any i in (1 .. #w1) : ($w2 at @w1[i] + 6)) and
      (for any i in (1 .. #v1) : ($v2 at @v1[i] + 8))
    ) or (
      (for any i in (1 .. #w1) : ($w2 at @w1[i] + 6)) and
      (for any i in (1 .. #n1) : ($n2 at @n1[i] + 9))
    ) or (
      (for any i in (1 .. #c1) : ($c2 at @c1[i] + 7)) and
      (for any i in (1 .. #v1) : ($v2 at @v1[i] + 8))
    ) or (
      (for any i in (1 .. #c1) : ($c2 at @c1[i] + 7)) and
      (for any i in (1 .. #n1) : ($n2 at @n1[i] + 9))
    ) or (
      (for any i in (1 .. #v1) : ($v2 at @v1[i] + 8)) and
      (for any i in (1 .. #n1) : ($n2 at @n1[i] + 9))
    )
}

rule proc_memory_scrape
{
  meta:
    tier = "weak"
    scope = "code"
    eco = "both"
    summary = "Code opens another process's memory, or names a tool that dumps credentials from memory."
  strings:
    $proc = "\x2fproc\x2f" ascii
    $mem = "\x2fmem" ascii
    $rpm1 = "ReadPro" ascii
    $rpm2 = "cessMemory" ascii
    $mimi = "\x6dimikatz" nocase ascii
    $pypy = "\x70ypykatz" nocase ascii
    $dump = "\x73ecretsdump" nocase ascii
    $lsass = "lsass.dmp" nocase ascii
  condition:
    (
      for any i in (1 .. #proc) : (
        @proc[i] + 6 < filesize and
        $mem in (@proc[i] + 6 .. @proc[i] + 30) and
        uint8(@proc[i]) == 0x2f
      )
    ) or (
      for any i in (1 .. #rpm1) : (
        @rpm1[i] + 7 < filesize and
        $rpm2 at @rpm1[i] + 7 and
        uint8(@rpm1[i]) == 0x52
      )
    ) or
    for any i in (1 .. #mimi) : (
      @mimi[i] < filesize and (uint8(@mimi[i]) == 0x6d or uint8(@mimi[i]) == 0x4d)
    ) or
    for any i in (1 .. #pypy) : (
      @pypy[i] < filesize and (uint8(@pypy[i]) == 0x70 or uint8(@pypy[i]) == 0x50)
    ) or
    for any i in (1 .. #dump) : (
      @dump[i] < filesize and (uint8(@dump[i]) == 0x73 or uint8(@dump[i]) == 0x53)
    ) or
    for any i in (1 .. #lsass) : (
      @lsass[i] < filesize and (uint8(@lsass[i]) == 0x6c or uint8(@lsass[i]) == 0x4c)
    )
}

rule mining
{
  meta:
    tier = "weak"
    scope = "code,manifest"
    eco = "both"
    summary = "A cryptocurrency miner pool address, or the xmrig miner name."
  strings:
    $stratum = "stratum+" ascii
    $tcp = "tcp:\x2f\x2f" ascii
    $ssl = "ssl:\x2f\x2f" ascii
    $tls = "tls:\x2f\x2f" ascii
    $xm1 = "\x78mrig" nocase ascii
    $pool1 = "\x73upportxmr.com" ascii
    $pool2 = "\x6dinexmr.com" ascii
    $pool3 = "\x6eanopool.org" ascii
    $pool4 = "2miners.com" ascii
    $pool5 = "moneroocean.stream" ascii
    $pool6 = "hashvault.pro" ascii
  condition:
    (
      for any i in (1 .. #stratum) : (
        $tcp at @stratum[i] + 8 or
        $ssl at @stratum[i] + 8 or
        $tls at @stratum[i] + 8
      )
    ) or
    $xm1 or
    $pool1 or
    $pool2 or
    $pool3 or
    $pool4 or
    $pool5 or
    $pool6
}

rule keylogger
{
  meta:
    tier = "weak"
    scope = "code"
    eco = "both"
    summary = "Code subscribes to keystrokes, or installs a keyboard hook."
  strings:
    $py = "pynput" ascii
    $keys = "keyboard" ascii
    $press = "\x6fn_press" ascii
    $hook1 = "SetWindows" ascii
    $hook2 = "HookEx" ascii
    $io = "iohook" ascii
    $ngl = "\x6eode-global-key-listener" ascii
    $gkl = "GlobalKeyboardListener" ascii
  condition:
    (
      for any i in (1 .. #py) : (
        $keys in (@py[i] .. @py[i] + 24)
      )
    ) or (
      for any i in (1 .. #press) : (
        $keys in (@press[i] - 24 .. @press[i]) or
        (@press[i] < 24 and $keys in (0 .. @press[i]))
      )
    ) or (
      for any i in (1 .. #hook1) : (
        $hook2 at @hook1[i] + 10
      )
    ) or
    $io or
    $ngl or
    $gkl
}

rule exec_runtime_pip
{
  meta:
    tier = "weak"
    scope = "py"
    eco = "pypi"
    summary = "Python launches pip install while the package is already running."
  strings:
    $pip = "pip" ascii
    $inst = "\x69nstall" ascii
    $sub = "subprocess." ascii
    $sys = "os.system" ascii
    $pop = "os.popen" ascii
    $internal = "pip._internal.main" ascii
  condition:
    (
      for any i in (1 .. #pip) : (
        $inst in (@pip[i] .. @pip[i] + 24) and
        (
          (@pip[i] >= 80 and (
            $sub in (@pip[i] - 80 .. @pip[i] + 40) or
            $sys in (@pip[i] - 80 .. @pip[i] + 40) or
            $pop in (@pip[i] - 80 .. @pip[i] + 40)
          )) or (
            @pip[i] < 80 and (
              $sub in (0 .. @pip[i] + 40) or
              $sys in (0 .. @pip[i] + 40) or
              $pop in (0 .. @pip[i] + 40)
            )
          )
        )
      )
    ) or (
      for any i in (1 .. #internal) : (
        $inst in (@internal[i] .. @internal[i] + 40)
      )
    )
}
