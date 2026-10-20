// Droppers, loaders, and other payloads that run after a package is installed.

rule npm_self_publish
{
  meta:
    tier = "weak"
    scope = "js,npm_manifest,shell"
    eco = "npm"
    summary = "Install code publishes a package back to the registry."
  strings:
    $npm = "\x6epm publish" ascii
    $pnpm = "pnpm publish" ascii
    $yarn = "yarn publish" ascii
    $bun = "bun publish" ascii
    $qn = "'npm'" ascii
    $qp = "'pnpm'" ascii
    $qy = "'yarn'" ascii
    $qb = "'bun'" ascii
    $pub = "'publish'" ascii
    $hook_pre = "\"preinstall\"" ascii
    $hook_in = "\"install\"" ascii
    $hook_post = "\"postinstall\"" ascii
    $hook_prep = "\"prepare\"" ascii
  condition:
    $npm or
    $pnpm or
    $yarn or
    $bun or
    (
      for any i in (1 .. #qn) : (
        $pub in (@qn[i] .. @qn[i] + 24)
      )
    ) or (
      for any i in (1 .. #qp) : (
        $pub in (@qp[i] .. @qp[i] + 24)
      )
    ) or (
      for any i in (1 .. #qy) : (
        $pub in (@qy[i] .. @qy[i] + 24)
      )
    ) or (
      for any i in (1 .. #qb) : (
        $pub in (@qb[i] .. @qb[i] + 24)
      )
    ) or (
      ($hook_pre or $hook_in or $hook_post or $hook_prep) and
      ($npm or $pnpm or $yarn)
    )
}

rule ci_workflow_write
{
  meta:
    tier = "weak"
    scope = "code"
    eco = "both"
    summary = "Code writes a CI pipeline file such as a workflow under the repository's CI directory."
  strings:
    $wf = "\x77riteFile" ascii
    $ap = "\x61ppendFile" ascii
    $open = "open(" ascii
    $mkdir = "mkdirSync" ascii
    $wt = "write_text(" ascii
    $dotw = ".write(" ascii
    $gh = ".github\x2fworkflows" ascii
    $ghb = ".github\\workflows" ascii
    $gl = ".gitlab-ci.yml" ascii
    $cc = ".circleci" ascii
    $az = "azure-pipelines.yml" ascii
  condition:
    (
      for any i in (1 .. #wf) : (@wf[i] < filesize) or
      for any i in (1 .. #ap) : (@ap[i] < filesize) or
      for any i in (1 .. #open) : (@open[i] < filesize) or
      for any i in (1 .. #mkdir) : (@mkdir[i] < filesize) or
      for any i in (1 .. #wt) : (@wt[i] < filesize) or
      for any i in (1 .. #dotw) : (@dotw[i] < filesize)
    ) and (
      for any i in (1 .. #gh) : (@gh[i] < filesize) or
      for any i in (1 .. #ghb) : (@ghb[i] < filesize) or
      for any i in (1 .. #gl) : (@gl[i] < filesize) or
      for any i in (1 .. #cc) : (@cc[i] < filesize) or
      for any i in (1 .. #az) : (@az[i] < filesize)
    )
}

rule onchain_loader
{
  meta:
    tier = "weak"
    scope = "code"
    eco = "both"
    summary = "Code reads a blockchain transaction and then runs the data it found."
  strings:
    $eth = "eth_getTransaction" ascii
    $tron = "api.trongrid.io" ascii
    $scan = "apilist.tronscan" ascii
    $bsc = "bsc-dataseed" ascii
    $apt = "aptoslabs.com\x2fv1" ascii
    $eval = "\x65val(" ascii
    $exec = "exec(" ascii
    $fn = "\x6eew Function" ascii
  condition:
  (
    for any i in (1 .. #eth) : (
      @eth[i] < filesize and
      @eth[i] >= 0 and
      uint8(@eth[i]) >= 0x09 and
      uint8(@eth[i]) <= 0x7e and
      uint8(@eth[i]) != 0x00 and
      uint8(@eth[i]) != 0x01 and
      uint8(@eth[i]) != 0x02 and
      uint8(@eth[i]) != 0x7f and
      not (@eth[i] > filesize)
    ) or
    for any i in (1 .. #tron) : (
      @tron[i] < filesize and
      @tron[i] >= 0 and
      uint8(@tron[i]) >= 0x09 and
      uint8(@tron[i]) <= 0x7e and
      uint8(@tron[i]) != 0x00 and
      uint8(@tron[i]) != 0x01 and
      uint8(@tron[i]) != 0x02 and
      uint8(@tron[i]) != 0x7f and
      not (@tron[i] > filesize)
    ) or
    for any i in (1 .. #scan) : (
      @scan[i] < filesize and
      @scan[i] >= 0 and
      uint8(@scan[i]) >= 0x09 and
      uint8(@scan[i]) <= 0x7e and
      uint8(@scan[i]) != 0x00 and
      uint8(@scan[i]) != 0x01 and
      uint8(@scan[i]) != 0x02 and
      uint8(@scan[i]) != 0x7f and
      not (@scan[i] > filesize)
    ) or
    for any i in (1 .. #bsc) : (
      @bsc[i] < filesize and
      @bsc[i] >= 0 and
      uint8(@bsc[i]) >= 0x09 and
      uint8(@bsc[i]) <= 0x7e and
      uint8(@bsc[i]) != 0x00 and
      uint8(@bsc[i]) != 0x01 and
      uint8(@bsc[i]) != 0x02 and
      uint8(@bsc[i]) != 0x7f and
      not (@bsc[i] > filesize)
    ) or
    for any i in (1 .. #apt) : (
      @apt[i] < filesize and
      @apt[i] >= 0 and
      uint8(@apt[i]) >= 0x09 and
      uint8(@apt[i]) <= 0x7e and
      uint8(@apt[i]) != 0x00 and
      uint8(@apt[i]) != 0x01 and
      uint8(@apt[i]) != 0x02 and
      uint8(@apt[i]) != 0x7f and
      not (@apt[i] > filesize)
    )
  ) and (
    for any i in (1 .. #eval) : (
      @eval[i] < filesize and
      @eval[i] >= 0 and
      uint8(@eval[i]) >= 0x09 and
      uint8(@eval[i]) <= 0x7e and
      uint8(@eval[i]) != 0x00 and
      uint8(@eval[i]) != 0x01 and
      uint8(@eval[i]) != 0x02 and
      uint8(@eval[i]) != 0x7f and
      not (@eval[i] > filesize)
    ) or
    for any i in (1 .. #exec) : (
      @exec[i] < filesize and
      @exec[i] >= 0 and
      uint8(@exec[i]) >= 0x09 and
      uint8(@exec[i]) <= 0x7e and
      uint8(@exec[i]) != 0x00 and
      uint8(@exec[i]) != 0x01 and
      uint8(@exec[i]) != 0x02 and
      uint8(@exec[i]) != 0x7f and
      not (@exec[i] > filesize)
    ) or
    for any i in (1 .. #fn) : (
      @fn[i] < filesize and
      @fn[i] >= 0 and
      uint8(@fn[i]) >= 0x09 and
      uint8(@fn[i]) <= 0x7e and
      uint8(@fn[i]) != 0x00 and
      uint8(@fn[i]) != 0x01 and
      uint8(@fn[i]) != 0x02 and
      uint8(@fn[i]) != 0x7f and
      not (@fn[i] > filesize)
    )
  )
}

rule self_delete_dropper
{
  meta:
    tier = "weak"
    scope = "code"
    eco = "both"
    summary = "The running file deletes itself after it starts."
  strings:
    $un = "unlink" ascii
    $rm = "rmSync" ascii
    $rm2 = "rm(" ascii
    $me = "__filename" ascii
    $arg = "process.argv[1]" ascii
    $osr = "os.remove" ascii
    $osu = "os.unlink" ascii
    $py = "__file__" ascii
    $argv0 = "sys.argv[0]" ascii
    $rmf = "rm -f" ascii
    $zero = "$0" ascii
  condition:
    (
      for any i in (1 .. #un) : (
        $me in (@un[i] - 80 .. @un[i] + 80) or
        $arg in (@un[i] - 80 .. @un[i] + 80)
      ) or
      for any i in (1 .. #rm) : (
        $me in (@rm[i] - 80 .. @rm[i] + 80) or
        $arg in (@rm[i] - 80 .. @rm[i] + 80)
      ) or
      for any i in (1 .. #rm2) : (
        $me in (@rm2[i] - 40 .. @rm2[i] + 40) or
        $arg in (@rm2[i] - 40 .. @rm2[i] + 40)
      )
    ) or (
      for any i in (1 .. #osr) : (
        $py in (@osr[i] - 120 .. @osr[i] + 120) or
        $argv0 in (@osr[i] - 120 .. @osr[i] + 120)
      ) or
      for any i in (1 .. #osu) : (
        $py in (@osu[i] - 120 .. @osu[i] + 120) or
        $argv0 in (@osu[i] - 120 .. @osu[i] + 120)
      )
    ) or (
      for any i in (1 .. #rmf) : (
        $zero in (@rmf[i] .. @rmf[i] + 16)
      )
    )
}

rule staged_dropper
{
  meta:
    tier = "weak"
    scope = "js"
    eco = "npm"
    summary = "Decoded bytes are written to a file and that file is then loaded or executed."
  strings:
    $b64 = "Buffer.from" ascii
    $tag64 = "'base64'" ascii
    $tag64d = "\"base64\"" ascii
    $taghex = "'hex'" ascii
    $atob = "atob(" ascii
    $write = "writeFileSync" ascii
    $req = "require(" ascii
    $spawn = "spawn(" ascii
    $execf = "\x65xecFile" ascii
    $fork = "fork(" ascii
  condition:
    (
      (
        for any i in (1 .. #b64) : (
          (
            $tag64 in (@b64[i] .. @b64[i] + 80) or
            $tag64d in (@b64[i] .. @b64[i] + 80) or
            $taghex in (@b64[i] .. @b64[i] + 80)
          ) and
          $write in (@b64[i] .. @b64[i] + 700) and
          (
            $req in (@b64[i] .. @b64[i] + 1500) or
            $spawn in (@b64[i] .. @b64[i] + 1500) or
            $execf in (@b64[i] .. @b64[i] + 1500) or
            $fork in (@b64[i] .. @b64[i] + 1500)
          )
        )
      ) or (
        for any i in (1 .. #atob) : (
          $write in (@atob[i] .. @atob[i] + 700) and
          (
            $req in (@atob[i] .. @atob[i] + 1500) or
            $spawn in (@atob[i] .. @atob[i] + 1500) or
            $execf in (@atob[i] .. @atob[i] + 1500) or
            $fork in (@atob[i] .. @atob[i] + 1500)
          )
        )
      )
    )
}

rule alt_runtime_fetch
{
  meta:
    tier = "weak"
    scope = "code,manifest"
    eco = "both"
    summary = "Install code downloads the Bun or Deno runtime."
  strings:
    $bun = "bun.sh\x2finstall" ascii
    $deno = "deno.land\x2finstall" ascii
    $bunrel = "oven-sh\x2fbun\x2freleases\x2fdownload" ascii
    $denorel = "denoland\x2fdeno\x2freleases\x2fdownload" ascii
  condition:
    for any i in (1 .. #bun) : (
      @bun[i] < filesize and
      @bun[i] >= 0 and
      uint8(@bun[i]) >= 0x09 and
      uint8(@bun[i]) <= 0x7e and
      uint8(@bun[i]) != 0x00 and
      uint8(@bun[i]) != 0x01 and
      uint8(@bun[i]) != 0x02 and
      uint8(@bun[i]) != 0x7f and
      not (@bun[i] > filesize)
    ) or
    for any i in (1 .. #deno) : (
      @deno[i] < filesize and
      @deno[i] >= 0 and
      uint8(@deno[i]) >= 0x09 and
      uint8(@deno[i]) <= 0x7e and
      uint8(@deno[i]) != 0x00 and
      uint8(@deno[i]) != 0x01 and
      uint8(@deno[i]) != 0x02 and
      uint8(@deno[i]) != 0x7f and
      not (@deno[i] > filesize)
    ) or
    for any i in (1 .. #bunrel) : (
      @bunrel[i] < filesize and
      @bunrel[i] >= 0 and
      uint8(@bunrel[i]) >= 0x09 and
      uint8(@bunrel[i]) <= 0x7e and
      uint8(@bunrel[i]) != 0x00 and
      uint8(@bunrel[i]) != 0x01 and
      uint8(@bunrel[i]) != 0x02 and
      uint8(@bunrel[i]) != 0x7f and
      not (@bunrel[i] > filesize)
    ) or
    for any i in (1 .. #denorel) : (
      @denorel[i] < filesize and
      @denorel[i] >= 0 and
      uint8(@denorel[i]) >= 0x09 and
      uint8(@denorel[i]) <= 0x7e and
      uint8(@denorel[i]) != 0x00 and
      uint8(@denorel[i]) != 0x01 and
      uint8(@denorel[i]) != 0x02 and
      uint8(@denorel[i]) != 0x7f and
      not (@denorel[i] > filesize)
    )
}

rule logic_bomb_geo
{
  meta:
    tier = "weak"
    scope = "code"
    eco = "both"
    summary = "A locale, time zone, or country check sits next to a call that deletes or overwrites files."
  strings:
    $tz = "resolvedOptions" ascii
    $lang = "navigator.language" ascii
    $intl = "Intl.DateTimeFormat" ascii
    $ip = "ipapi.co\x2fcountry" ascii
    $cc = "country_code" ascii
    $rm = "rm -rf" ascii
    $rms = "rmSync" ascii
    $rim = "\x72imraf" ascii
    $un = "unlinkSync" ascii
    $wf = "writeFileSync" ascii
    $tree = "shutil.rmtree" ascii
  condition:
    for any i in (1 .. #tz) : (
      (
        $rm in (@tz[i] .. @tz[i] + 600) or
        $rms in (@tz[i] .. @tz[i] + 600) or
        $rim in (@tz[i] .. @tz[i] + 600) or
        $un in (@tz[i] .. @tz[i] + 600) or
        $wf in (@tz[i] .. @tz[i] + 600) or
        $tree in (@tz[i] .. @tz[i] + 600)
      )
    ) or
    for any i in (1 .. #lang) : (
      $rm in (@lang[i] .. @lang[i] + 600) or
      $rms in (@lang[i] .. @lang[i] + 600) or
      $un in (@lang[i] .. @lang[i] + 600) or
      $wf in (@lang[i] .. @lang[i] + 600) or
      $tree in (@lang[i] .. @lang[i] + 600)
    ) or
    for any i in (1 .. #intl) : (
      $rm in (@intl[i] .. @intl[i] + 600) or
      $rms in (@intl[i] .. @intl[i] + 600) or
      $un in (@intl[i] .. @intl[i] + 600) or
      $wf in (@intl[i] .. @intl[i] + 600) or
      $tree in (@intl[i] .. @intl[i] + 600)
    ) or
    for any i in (1 .. #ip) : (
      $rm in (@ip[i] .. @ip[i] + 600) or
      $rms in (@ip[i] .. @ip[i] + 600) or
      $tree in (@ip[i] .. @ip[i] + 600)
    ) or
    for any i in (1 .. #cc) : (
      $rm in (@cc[i] .. @cc[i] + 600) or
      $rms in (@cc[i] .. @cc[i] + 600) or
      $un in (@cc[i] .. @cc[i] + 600) or
      $tree in (@cc[i] .. @cc[i] + 600)
    )
}

rule stego_exec
{
  meta:
    tier = "weak"
    scope = "code"
    eco = "both"
    summary = "Hidden data is pulled out of an image and then executed."
  strings:
    $st = "\x73tegano" ascii
    $lsb = "lsb.reveal" ascii
    $stg = "steggy" ascii
    $pix = "getPixelColor" ascii
    $gp = "getpixel" ascii
    $eval = "\x65val(" ascii
    $exec = "exec(" ascii
    $fn = "\x6eew Function" ascii
  condition:
  (
    for any i in (1 .. #st) : (
      @st[i] < filesize and
      @st[i] >= 0 and
      uint8(@st[i]) >= 0x09 and
      uint8(@st[i]) <= 0x7e and
      uint8(@st[i]) != 0x00 and
      uint8(@st[i]) != 0x01 and
      uint8(@st[i]) != 0x02 and
      uint8(@st[i]) != 0x7f and
      not (@st[i] > filesize)
    ) or
    for any i in (1 .. #lsb) : (
      @lsb[i] < filesize and
      @lsb[i] >= 0 and
      uint8(@lsb[i]) >= 0x09 and
      uint8(@lsb[i]) <= 0x7e and
      uint8(@lsb[i]) != 0x00 and
      uint8(@lsb[i]) != 0x01 and
      uint8(@lsb[i]) != 0x02 and
      uint8(@lsb[i]) != 0x7f and
      not (@lsb[i] > filesize)
    ) or
    for any i in (1 .. #stg) : (
      @stg[i] < filesize and
      @stg[i] >= 0 and
      uint8(@stg[i]) >= 0x09 and
      uint8(@stg[i]) <= 0x7e and
      uint8(@stg[i]) != 0x00 and
      uint8(@stg[i]) != 0x01 and
      uint8(@stg[i]) != 0x02 and
      uint8(@stg[i]) != 0x7f and
      not (@stg[i] > filesize)
    ) or
    for any i in (1 .. #pix) : (
      @pix[i] < filesize and
      @pix[i] >= 0 and
      uint8(@pix[i]) >= 0x09 and
      uint8(@pix[i]) <= 0x7e and
      uint8(@pix[i]) != 0x00 and
      uint8(@pix[i]) != 0x01 and
      uint8(@pix[i]) != 0x02 and
      uint8(@pix[i]) != 0x7f and
      not (@pix[i] > filesize)
    ) or
    for any i in (1 .. #gp) : (
      @gp[i] < filesize and
      @gp[i] >= 0 and
      uint8(@gp[i]) >= 0x09 and
      uint8(@gp[i]) <= 0x7e and
      uint8(@gp[i]) != 0x00 and
      uint8(@gp[i]) != 0x01 and
      uint8(@gp[i]) != 0x02 and
      uint8(@gp[i]) != 0x7f and
      not (@gp[i] > filesize)
    )
  ) and (
    for any i in (1 .. #eval) : (
      @eval[i] < filesize and
      @eval[i] >= 0 and
      uint8(@eval[i]) >= 0x09 and
      uint8(@eval[i]) <= 0x7e and
      uint8(@eval[i]) != 0x00 and
      uint8(@eval[i]) != 0x01 and
      uint8(@eval[i]) != 0x02 and
      uint8(@eval[i]) != 0x7f and
      not (@eval[i] > filesize)
    ) or
    for any i in (1 .. #exec) : (
      @exec[i] < filesize and
      @exec[i] >= 0 and
      uint8(@exec[i]) >= 0x09 and
      uint8(@exec[i]) <= 0x7e and
      uint8(@exec[i]) != 0x00 and
      uint8(@exec[i]) != 0x01 and
      uint8(@exec[i]) != 0x02 and
      uint8(@exec[i]) != 0x7f and
      not (@exec[i] > filesize)
    ) or
    for any i in (1 .. #fn) : (
      @fn[i] < filesize and
      @fn[i] >= 0 and
      uint8(@fn[i]) >= 0x09 and
      uint8(@fn[i]) <= 0x7e and
      uint8(@fn[i]) != 0x00 and
      uint8(@fn[i]) != 0x01 and
      uint8(@fn[i]) != 0x02 and
      uint8(@fn[i]) != 0x7f and
      not (@fn[i] > filesize)
    )
  )
}

rule clipboard_read
{
  meta:
    tier = "info"
    scope = "code"
    eco = "both"
    summary = "The clipboard is read."
  strings:
    $a = "pyperclip.paste" ascii
    $b = "clipboardy" ascii
    $c = "clipboard.readText" ascii
    $d = "read_clipboard" ascii
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
    ) or
    for any i in (1 .. #d) : (
      @d[i] < filesize and
      @d[i] >= 0 and
      uint8(@d[i]) >= 0x09 and
      uint8(@d[i]) <= 0x7e and
      uint8(@d[i]) != 0x00 and
      uint8(@d[i]) != 0x01 and
      uint8(@d[i]) != 0x02 and
      uint8(@d[i]) != 0x7f and
      not (@d[i] > filesize)
    )
}
