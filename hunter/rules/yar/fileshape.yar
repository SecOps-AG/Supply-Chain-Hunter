// Files a package reads, writes, or destroys, and hooks that run on their own.

rule fs_sensitive_read
{
  meta:
    tier = "weak"
    scope = "code"
    eco = "both"
    summary = "A credential file, a browser store, or a wallet path is named."
  strings:
    $a = ".\x6epmrc" ascii
    $b = ".\x70ypirc" ascii
    $c = ".netrc" ascii
    $d = ".git-credentials" ascii
    $e = ".aws\x2fcredentials" ascii
    $f = ".aws\\credentials" ascii
    $g = "credentials.db" ascii
    $h = "application_default_credentials.json" ascii
    $i = "accessTokens" ascii
    $j = "msal_token_cache" ascii
    $k = "\x2fetc\x2fshadow" ascii
    $l = "Login Data" ascii
    $m = "Local State" ascii
    $n = "key4.db" ascii
    $o = "logins.json" ascii
    $p = "cookies.sqlite" ascii
    $q = "wallet.dat" ascii
    $r = "exodus.wallet" ascii
    $s = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii
    $t = "Electrum" ascii
  condition:
    $a or $b or $c or $d or $e or $f or $g or $h or $i or $j or $k or $l or $m or $n or $o or $p or $q or $r or $s or
    (
      for any i in (1 .. #t) : (
        @t[i] < filesize
      )
    )
}

rule fs_autostart_write
{
  meta:
    tier = "weak"
    scope = "code"
    eco = "both"
    summary = "A startup file, a launch agent, or a Run key is written."
  strings:
    $w = "\x77riteFile" ascii
    $a = "\x61ppendFile" ascii
    $o = "open(" ascii
    $redir = ">>" ascii
    $rc = ".\x62ashrc" ascii
    $zsh = ".zshrc" ascii
    $bash = ".\x62ash_profile" ascii
    $prof = ".profile" ascii
    $la = "LaunchAgents" ascii
    $ld = "LaunchDaemons" ascii
    $rcl = "\x2fetc\x2frc.local" ascii
    $init = "\x2fetc\x2finit.d" ascii
    $sys = "systemd\x2f" ascii
    $auto = ".config\x2fautostart" ascii
    $reg = "reg add" nocase ascii
    $win = "winreg.SetValue" ascii
    $run = "CurrentVersion" ascii
    $cron = "crontab" ascii
  condition:
    (
      ($w or $a or $o or $redir) and
      ($rc or $zsh or $bash or $prof or $la or $ld or $rcl or $init or $sys or $auto)
    ) or (
      ($reg or $win) and $run
    ) or (
      for any i in (1 .. #cron) : (
        $cron in (@cron[i] + 4 .. @cron[i] + 80)
      )
    )
}

rule fs_wiper
{
  meta:
    tier = "weak"
    scope = "code,manifest"
    eco = "both"
    summary = "A command that deletes the disk root, the home directory, or overwrites a raw device."
  strings:
    $rm = "rm -rf \x2f" ascii
    $rmh = "rm -rf ~" ascii
    $rmd = "rm -rf $" ascii
    $rms = "rm -rf *" ascii
    $rm2 = "rm -fr \x2f" ascii
    $rm2h = "rm -fr ~" ascii
    $rm2d = "rm -fr $" ascii
    $rm2s = "rm -fr *" ascii
    $tree = "shutil.rmtree" ascii
    $slash = "'\x2f'" ascii
    $slash2 = "\"\x2f\"" ascii
    $tilde = "expanduser" ascii
    $ph = "Path.home" ascii
    $dd = "dd if=\x2fdev\x2f" ascii
    $zero = "of=\x2fdev\x2f" ascii
    $shred = "shred " ascii
    $dev = "\x2fdev\x2f" ascii
  condition:
    (
      $rm or $rmh or $rmd or $rms or $rm2 or $rm2h or $rm2d or $rm2s
    ) or (
      $tree and ($slash or $slash2 or $tilde or $ph)
    ) or (
      for any i in (1 .. #dd) : (
        $zero in (@dd[i] .. @dd[i] + 40)
      )
    ) or (
      for any i in (1 .. #shred) : (
        $dev in (@shred[i] .. @shred[i] + 24)
      )
    )
}

rule gyp_command_exec
{
  meta:
    tier = "weak"
    scope = "gyp"
    eco = "npm"
    summary = "A native build file runs a shell command while compiling."
  strings:
    $exp = "<!(" ascii
    $exp2 = "<!@(" ascii
    $act = "\"action\"" ascii
    $curl = "curl" ascii
    $wget = "wget" ascii
    $http = "http:\x2f\x2f" ascii
    $https = "https:\x2f\x2f" ascii
    $node = "\x6eode -e" ascii
    $sh = "sh -c" ascii
    $bash = "bash -c" ascii
    $ps = "powershell" ascii
    $py = "python -c" ascii
    $py3 = "python3 -c" ascii
    $cert = "certutil" ascii
  condition:
    (
      for any i in (1 .. #exp) : (
        $curl in (@exp[i] .. @exp[i] + 200) or
        $wget in (@exp[i] .. @exp[i] + 200) or
        $http in (@exp[i] .. @exp[i] + 200) or
        $https in (@exp[i] .. @exp[i] + 200) or
        $node in (@exp[i] .. @exp[i] + 200) or
        $sh in (@exp[i] .. @exp[i] + 200) or
        $bash in (@exp[i] .. @exp[i] + 200) or
        $ps in (@exp[i] .. @exp[i] + 200) or
        $py in (@exp[i] .. @exp[i] + 200) or
        $py3 in (@exp[i] .. @exp[i] + 200) or
        $cert in (@exp[i] .. @exp[i] + 200)
      )
    ) or (
      for any i in (1 .. #exp2) : (
        $curl in (@exp2[i] .. @exp2[i] + 200) or
        $wget in (@exp2[i] .. @exp2[i] + 200) or
        $http in (@exp2[i] .. @exp2[i] + 200) or
        $node in (@exp2[i] .. @exp2[i] + 200) or
        $sh in (@exp2[i] .. @exp2[i] + 200) or
        $ps in (@exp2[i] .. @exp2[i] + 200)
      )
    ) or (
      for any i in (1 .. #act) : (
        $curl in (@act[i] .. @act[i] + 300) or
        $wget in (@act[i] .. @act[i] + 300) or
        $http in (@act[i] .. @act[i] + 300) or
        $https in (@act[i] .. @act[i] + 300) or
        $node in (@act[i] .. @act[i] + 300) or
        $sh in (@act[i] .. @act[i] + 300) or
        $ps in (@act[i] .. @act[i] + 300) or
        $cert in (@act[i] .. @act[i] + 300)
      )
    )
}

rule agent_hook_config
{
  meta:
    tier = "weak"
    scope = "agent_config"
    eco = "both"
    summary = "An agent config ships hooks or a command that the tool will run."
  strings:
    $hooks = "\"hooks\"" ascii
    $cmd = "\"command\"" ascii
  condition:
    for any i in (1 .. #hooks) : (
      @hooks[i] < filesize and
      @hooks[i] >= 0 and
      uint8(@hooks[i]) >= 0x09 and
      uint8(@hooks[i]) <= 0x7e and
      uint8(@hooks[i]) != 0x00 and
      uint8(@hooks[i]) != 0x01 and
      uint8(@hooks[i]) != 0x02 and
      uint8(@hooks[i]) != 0x7f and
      not (@hooks[i] > filesize)
    ) or
    for any i in (1 .. #cmd) : (
      @cmd[i] < filesize and
      @cmd[i] >= 0 and
      uint8(@cmd[i]) >= 0x09 and
      uint8(@cmd[i]) <= 0x7e and
      uint8(@cmd[i]) != 0x00 and
      uint8(@cmd[i]) != 0x01 and
      uint8(@cmd[i]) != 0x02 and
      uint8(@cmd[i]) != 0x7f and
      not (@cmd[i] > filesize)
    )
}

rule vscode_folder_open
{
  meta:
    tier = "weak"
    scope = "agent_config"
    eco = "both"
    summary = "An editor task is set to run as soon as the folder is opened."
  strings:
    $run = "\"runOn\"" ascii
    $open = "\"folderOpen\"" ascii
  condition:
    for any i in (1 .. #run) : (
      @run[i] + 6 < filesize and
      $open in (@run[i] .. @run[i] + 24) and
      uint8(@run[i]) == 0x22 and
      uint8(@run[i] + 1) == 0x72 and
      uint8(@run[i] + 2) == 0x75 and
      uint8(@run[i] + 3) == 0x6e and
      uint8(@run[i] + 4) == 0x4f and
      uint8(@run[i] + 5) == 0x6e and
      uint8(@run[i] + 6) == 0x22 and
      @run[i] + 7 < filesize and
      uint8(@run[i] + 1) != 0x00 and
      uint8(@run[i] + 2) != 0x00 and
      uint8(@run[i] + 3) != 0x00
    )
}

rule install_fromcharcode
{
  meta:
    tier = "weak"
    scope = "manifest"
    eco = "both"
    summary = "An install script hides text as character codes or hex escapes."
  strings:
    $fcc = "\x66romCharCode" ascii
    $hex = /(\x5c\x78[0-9a-fA-F][0-9a-fA-F]){3}/
  condition:
    for any i in (1 .. #fcc) : (
      @fcc[i] < filesize and
      @fcc[i] >= 0 and
      uint8(@fcc[i]) >= 0x09 and
      uint8(@fcc[i]) <= 0x7e and
      uint8(@fcc[i]) != 0x00 and
      uint8(@fcc[i]) != 0x01 and
      uint8(@fcc[i]) != 0x02 and
      uint8(@fcc[i]) != 0x7f and
      not (@fcc[i] > filesize)
    ) or
    for any i in (1 .. #hex) : (
      @hex[i] < filesize and
      @hex[i] >= 0 and
      uint8(@hex[i]) >= 0x09 and
      uint8(@hex[i]) <= 0x7e and
      uint8(@hex[i]) != 0x00 and
      uint8(@hex[i]) != 0x01 and
      uint8(@hex[i]) != 0x02 and
      uint8(@hex[i]) != 0x7f and
      not (@hex[i] > filesize)
    )
}
