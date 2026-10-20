// Destinations a package reaches out to.

rule net_exfil_messenger
{
  meta:
    tier = "weak"
    scope = "code,manifest,workflow"
    eco = "both"
    comments = "skip"
    summary = "A Telegram bot API or a Discord webhook URL is built into the release."
  strings:
    $bot = "egram.org\x2fbot" ascii
    $botq = "org\x2fbot' +" ascii
    $botq2 = "org\x2fbot\" +" ascii
    $botq3 = "org\x2fbot +" ascii
    $hook = "webhooks\x2f" ascii
  condition:
    for any i in (1 .. #bot) : (
      @bot[i] + 18 < filesize and
      uint8(@bot[i] + 13) >= 0x30 and uint8(@bot[i] + 13) <= 0x39 and
      uint8(@bot[i] + 14) >= 0x30 and uint8(@bot[i] + 14) <= 0x39 and
      uint8(@bot[i] + 15) >= 0x30 and uint8(@bot[i] + 15) <= 0x39 and
      uint8(@bot[i] + 16) >= 0x30 and uint8(@bot[i] + 16) <= 0x39 and
      uint8(@bot[i] + 17) >= 0x30 and uint8(@bot[i] + 17) <= 0x39 and
      uint8(@bot[i] + 18) >= 0x30 and uint8(@bot[i] + 18) <= 0x39
    ) or
    for any i in (1 .. #botq) : (@botq[i] < filesize) or
    for any i in (1 .. #botq2) : (@botq2[i] < filesize) or
    for any i in (1 .. #botq3) : (@botq3[i] < filesize) or
    for any i in (1 .. #hook) : (
      @hook[i] + 16 < filesize and
      uint8(@hook[i] + 9) >= 0x30 and uint8(@hook[i] + 9) <= 0x39 and
      uint8(@hook[i] + 10) >= 0x30 and uint8(@hook[i] + 10) <= 0x39 and
      uint8(@hook[i] + 11) >= 0x30 and uint8(@hook[i] + 11) <= 0x39 and
      uint8(@hook[i] + 12) >= 0x30 and uint8(@hook[i] + 12) <= 0x39 and
      uint8(@hook[i] + 13) >= 0x30 and uint8(@hook[i] + 13) <= 0x39 and
      uint8(@hook[i] + 14) >= 0x30 and uint8(@hook[i] + 14) <= 0x39 and
      uint8(@hook[i] + 15) >= 0x30 and uint8(@hook[i] + 15) <= 0x39 and
      uint8(@hook[i] + 16) >= 0x30 and uint8(@hook[i] + 16) <= 0x39
    )
}

rule net_oast_host
{
  meta:
    tier = "weak"
    scope = "code,manifest,workflow"
    eco = "both"
    comments = "skip"
    summary = "An out-of-band callback host used by request-capture tools."
  strings:
    $a = "\x6fastify.com" nocase ascii
    $b = "\x62urpcollaborator.net" nocase ascii
    $c = "\x69nteract.sh" nocase ascii
    $d = "\x6fast.fun" nocase ascii
    $e = "\x6fast.me" nocase ascii
    $f = "\x6fast.pro" nocase ascii
    $g = "\x6fast.live" nocase ascii
    $h = "\x6fast.site" nocase ascii
    $i = "\x6fast.online" nocase ascii
    $j = "dnslog.cn" nocase ascii
    $k = "ceye.io" nocase ascii
    $l = "canarytokens.com" nocase ascii
    $m = "\x77ebhook.site" nocase ascii
    $n = "\x70ipedream.net" nocase ascii
    $o = "\x72equestbin.net" nocase ascii
    $p = "\x72equestbin.com" nocase ascii
    $q = "\x62eeceptor.com" nocase ascii
    $r = ".m.pipedream" nocase ascii
  condition:
    for any i in (1 .. #a) : (@a[i] < filesize) or
    for any i in (1 .. #b) : (@b[i] < filesize) or
    for any i in (1 .. #c) : (@c[i] < filesize) or
    for any i in (1 .. #d) : (@d[i] < filesize) or
    for any i in (1 .. #e) : (@e[i] < filesize) or
    for any i in (1 .. #f) : (@f[i] < filesize) or
    for any i in (1 .. #g) : (@g[i] < filesize) or
    for any i in (1 .. #h) : (@h[i] < filesize) or
    for any i in (1 .. #i) : (@i[i] < filesize) or
    for any i in (1 .. #j) : (@j[i] < filesize) or
    for any i in (1 .. #k) : (@k[i] < filesize) or
    for any i in (1 .. #l) : (@l[i] < filesize) or
    for any i in (1 .. #m) : (@m[i] < filesize) or
    for any i in (1 .. #n) : (@n[i] < filesize) or
    for any i in (1 .. #o) : (@o[i] < filesize) or
    for any i in (1 .. #p) : (@p[i] < filesize) or
    for any i in (1 .. #q) : (@q[i] < filesize) or
    for any i in (1 .. #r) : (@r[i] < filesize)
}

rule net_tunnel_host
{
  meta:
    tier = "weak"
    scope = "code,manifest"
    eco = "both"
    comments = "skip"
    summary = "A public tunnel hostname that forwards traffic to a local port."
  strings:
    $ng = "\x6egrok.io" nocase ascii
    $nf = "\x6egrok-free.app" nocase ascii
    $nd = "ngrok-free.dev" nocase ascii
    $na = "ngrok.app" nocase ascii
    $nv = "ngrok.dev" nocase ascii
    $cf = "\x74rycloudflare.com" nocase ascii
    $lr = "\x6cocalhost.run" nocase ascii
    $sv = "\x73erveo.net" nocase ascii
    $ply = ".ply.gg" nocase ascii
  condition:
    for any i in (1 .. #ng) : (@ng[i] < filesize) or
    for any i in (1 .. #nf) : (@nf[i] < filesize) or
    for any i in (1 .. #nd) : (@nd[i] < filesize) or
    for any i in (1 .. #na) : (@na[i] < filesize) or
    for any i in (1 .. #nv) : (@nv[i] < filesize) or
    for any i in (1 .. #cf) : (@cf[i] < filesize) or
    for any i in (1 .. #lr) : (@lr[i] < filesize) or
    for any i in (1 .. #sv) : (@sv[i] < filesize) or
    for any i in (1 .. #ply) : (@ply[i] < filesize)
}

rule net_paste_drop
{
  meta:
    tier = "weak"
    scope = "code,manifest"
    eco = "both"
    comments = "skip"
    summary = "A paste site or a file-drop host used to fetch or post a payload."
  strings:
    $a = "pastebin.com\x2fraw" nocase ascii
    $b = "\x68astebin.com" nocase ascii
    $c = "\x74ransfer.sh" nocase ascii
    $d = "catbox.moe" nocase ascii
    $e = "sendspace.com" nocase ascii
    $f = "paste.ee" nocase ascii
    $g = "termbin.com" nocase ascii
    $h = "0x0.st" nocase ascii
    $i = "file.io\x2f" nocase ascii
    $j = "gofile.io" nocase ascii
    $k = "temp.sh" nocase ascii
  condition:
    for any i in (1 .. #a) : (@a[i] < filesize) or
    for any i in (1 .. #b) : (@b[i] < filesize) or
    for any i in (1 .. #c) : (@c[i] < filesize) or
    for any i in (1 .. #d) : (@d[i] < filesize) or
    for any i in (1 .. #e) : (@e[i] < filesize) or
    for any i in (1 .. #f) : (@f[i] < filesize) or
    for any i in (1 .. #g) : (@g[i] < filesize) or
    for any i in (1 .. #h) : (@h[i] < filesize) or
    for any i in (1 .. #i) : (@i[i] < filesize) or
    for any i in (1 .. #j) : (@j[i] < filesize) or
    for any i in (1 .. #k) : (@k[i] < filesize)
}

rule net_ip_lookup
{
  meta:
    tier = "weak"
    scope = "code"
    eco = "both"
    comments = "skip"
    summary = "A public service that returns this machine's address."
  strings:
    $a = "ipinfo.io" nocase ascii
    $b = "ifconfig.me" nocase ascii
    $c = "api.ipify.org" nocase ascii
    $d = "api64.ipify.org" nocase ascii
    $e = "checkip.amazonaws.com" nocase ascii
    $f = "icanhazip.com" nocase ascii
    $g = "ipapi.co" nocase ascii
    $h = "ip-api.com" nocase ascii
  condition:
    for any i in (1 .. #a) : (@a[i] < filesize) or
    for any i in (1 .. #b) : (@b[i] < filesize) or
    for any i in (1 .. #c) : (@c[i] < filesize) or
    for any i in (1 .. #d) : (@d[i] < filesize) or
    for any i in (1 .. #e) : (@e[i] < filesize) or
    for any i in (1 .. #f) : (@f[i] < filesize) or
    for any i in (1 .. #g) : (@g[i] < filesize) or
    for any i in (1 .. #h) : (@h[i] < filesize)
}

rule net_shortener
{
  meta:
    tier = "weak"
    scope = "code"
    eco = "both"
    comments = "skip"
    summary = "A shortened URL inside program text."
  strings:
    $http = "http:\x2f\x2f" ascii
    $https = "https:\x2f\x2f" ascii
    $a = "bit.ly\x2f" ascii
    $b = "tinyurl.com\x2f" ascii
    $c = "is.gd\x2f" ascii
    $d = "t.ly\x2f" ascii
    $e = "cutt.ly\x2f" ascii
    $f = "rb.gy\x2f" ascii
    $g = "shorturl.at\x2f" ascii
  condition:
    (
      for any i in (1 .. #a) : (
        (@a[i] >= 8 and ($https at @a[i] - 8 or $http at @a[i] - 7)) or
        (@a[i] >= 7 and @a[i] < 8 and $http at @a[i] - 7)
      )
    ) or (
      for any i in (1 .. #b) : (
        (@b[i] >= 8 and ($https at @b[i] - 8 or $http at @b[i] - 7))
      )
    ) or (
      for any i in (1 .. #c) : (
        (@c[i] >= 8 and ($https at @c[i] - 8 or $http at @c[i] - 7))
      )
    ) or (
      for any i in (1 .. #d) : (
        (@d[i] >= 8 and ($https at @d[i] - 8 or $http at @d[i] - 7))
      )
    ) or (
      for any i in (1 .. #e) : (
        (@e[i] >= 8 and ($https at @e[i] - 8 or $http at @e[i] - 7))
      )
    ) or (
      for any i in (1 .. #f) : (
        (@f[i] >= 8 and ($https at @f[i] - 8 or $http at @f[i] - 7))
      )
    ) or (
      for any i in (1 .. #g) : (
        (@g[i] >= 8 and ($https at @g[i] - 8 or $http at @g[i] - 7))
      )
    )
}

rule net_abused_tld
{
  meta:
    tier = "weak"
    scope = "code"
    eco = "both"
    comments = "skip"
    summary = "An http URL whose host ends in a top-level domain often used for short-lived hosts."
  strings:
    $http = "http:\x2f\x2f" nocase ascii
    $https = "https:\x2f\x2f" nocase ascii
    $a = ".xyz\x2f" nocase ascii
    $b = ".xyz'" nocase ascii
    $c = ".xyz\"" nocase ascii
    $d = ".tk\x2f" nocase ascii
    $e = ".ml\x2f" nocase ascii
    $f = ".ga\x2f" nocase ascii
    $g = ".cf\x2f" nocase ascii
    $h = ".gq\x2f" nocase ascii
    $i = ".pw\x2f" nocase ascii
    $j = ".top\x2f" nocase ascii
    $k = ".icu\x2f" nocase ascii
    $l = ".click\x2f" nocase ascii
    $m = ".cam\x2f" nocase ascii
    $n = ".rest\x2f" nocase ascii
    $o = ".buzz\x2f" nocase ascii
  condition:
    (
      for any i in (1 .. #https) : (
        $a in (@https[i] .. @https[i] + 70) or
        $b in (@https[i] .. @https[i] + 70) or
        $c in (@https[i] .. @https[i] + 70) or
        $d in (@https[i] .. @https[i] + 70) or
        $e in (@https[i] .. @https[i] + 70) or
        $f in (@https[i] .. @https[i] + 70) or
        $g in (@https[i] .. @https[i] + 70) or
        $h in (@https[i] .. @https[i] + 70) or
        $i in (@https[i] .. @https[i] + 70) or
        $j in (@https[i] .. @https[i] + 70) or
        $k in (@https[i] .. @https[i] + 70) or
        $l in (@https[i] .. @https[i] + 70) or
        $m in (@https[i] .. @https[i] + 70) or
        $n in (@https[i] .. @https[i] + 70) or
        $o in (@https[i] .. @https[i] + 70)
      )
    ) or (
      for any i in (1 .. #http) : (
        $a in (@http[i] .. @http[i] + 70) or
        $d in (@http[i] .. @http[i] + 70) or
        $j in (@http[i] .. @http[i] + 70) or
        $k in (@http[i] .. @http[i] + 70)
      )
    )
}

rule net_raw_ip_url
{
  meta:
    tier = "weak"
    scope = "code,manifest"
    eco = "both"
    comments = "skip"
    confirm = "public_ip_url"
    summary = "An http URL aimed at a numeric address instead of a hostname."
  strings:
    $http = /\x68\x74\x74\x70\x3a\x2f\x2f([0-9]{1,3}\.){3}[0-9]{1,3}/
    $https = /\x68\x74\x74\x70\x73\x3a\x2f\x2f([0-9]{1,3}\.){3}[0-9]{1,3}/
  condition:
    for any i in (1 .. #http) : (
      @http[i] + 10 < filesize and
      uint8(@http[i]) == 0x68 and
      uint8(@http[i] + 1) == 0x74 and
      uint8(@http[i] + 2) == 0x74 and
      uint8(@http[i] + 3) == 0x70 and
      uint8(@http[i] + 4) == 0x3a
    ) or
    for any i in (1 .. #https) : (
      @https[i] + 11 < filesize and
      uint8(@https[i]) == 0x68 and
      uint8(@https[i] + 4) == 0x73 and
      uint8(@https[i] + 5) == 0x3a
    )
}

rule net_sysinfo_send
{
  meta:
    tier = "weak"
    scope = "code"
    eco = "both"
    summary = "The host or user name is read in the same added code that opens a network call."
  strings:
    $h1 = "os.hostname(" ascii
    $h2 = "os.userInfo(" ascii
    $h3 = "os.homedir(" ascii
    $h4 = "socket.gethostname" ascii
    $h5 = "getpass.getuser" ascii
    $h6 = "platform.node" ascii
    $h7 = "os.getlogin(" ascii
    $h8 = "os.uname(" ascii
    $n1 = "\x66etch(" ascii
    $n2 = "\x68ttp.request" ascii
    $n3 = "\x68ttps.request" ascii
    $n4 = "http.get" ascii
    $n5 = "https.get" ascii
    $n6 = "axios" ascii
    $n7 = "requests.post" ascii
    $n8 = "requests.get" ascii
    $n9 = "requests.put" ascii
    $n10 = "urlopen" ascii
    $n11 = "urllib.request" ascii
    $n12 = "XMLHttpRequest" ascii
    $n13 = "socket.connect" ascii
    $n14 = "socket.create_connection" ascii
    $n15 = "socket.send" ascii
  condition:
    ($h1 or $h2 or $h3 or $h4 or $h5 or $h6 or $h7 or $h8) and
    ($n1 or $n2 or $n3 or $n4 or $n5 or $n6 or $n7 or $n8 or $n9 or $n10 or $n11 or $n12 or $n13 or $n14 or $n15)
}

rule net_dns_exfil
{
  meta:
    tier = "weak"
    scope = "code"
    eco = "both"
    summary = "A DNS lookup whose name is built from data, not a fixed host."
  strings:
    $g1 = "gethostbyname" ascii
    $g2 = "getaddrinfo" ascii
    $f = "f\"" ascii
    $f2 = "f'" ascii
    $plus = "+ \"" ascii
    $plus2 = "+ '" ascii
    $fmt = ".format(" ascii
    $dns = "dns.lookup" ascii
    $dns2 = "dns.resolve" ascii
    $brace = "${" ascii
    $ns = "nslookup" ascii
    $dig = "dig " ascii
  condition:
    (
      ($g1 or $g2) and ($f or $f2 or $plus or $plus2 or $fmt)
    ) or (
      ($dns or $dns2) and ($brace or $plus or $plus2 or $f or $f2)
    ) or
    for any i in (1 .. #ns) : (
      @ns[i] + 70 < filesize and
      for any k in (0 .. 60) : (
        uint8(@ns[i] + 8 + k) == 0x24 and
        (
          (uint8(@ns[i] + 9 + k) >= 0x41 and uint8(@ns[i] + 9 + k) <= 0x5a) or
          (uint8(@ns[i] + 9 + k) >= 0x61 and uint8(@ns[i] + 9 + k) <= 0x7a) or
          uint8(@ns[i] + 9 + k) == 0x5f or
          uint8(@ns[i] + 9 + k) == 0x28 or
          uint8(@ns[i] + 9 + k) == 0x7b
        )
      )
    ) or
    for any i in (1 .. #dig) : (
      @dig[i] + 66 < filesize and
      for any k in (0 .. 60) : (
        uint8(@dig[i] + 4 + k) == 0x24 and
        (
          (uint8(@dig[i] + 5 + k) >= 0x41 and uint8(@dig[i] + 5 + k) <= 0x5a) or
          (uint8(@dig[i] + 5 + k) >= 0x61 and uint8(@dig[i] + 5 + k) <= 0x7a) or
          uint8(@dig[i] + 5 + k) == 0x5f or
          uint8(@dig[i] + 5 + k) == 0x28 or
          uint8(@dig[i] + 5 + k) == 0x7b
        )
      )
    )
}

rule cloud_imds
{
  meta:
    tier = "weak"
    scope = "code,manifest"
    eco = "both"
    comments = "skip"
    summary = "The cloud instance metadata address, including the link-local endpoint."
  strings:
    $a = "169.254.169.254" ascii
    $b = "169.254.170.2" ascii
    $c = "metadata.google.internal" ascii
    $d = "fd00:ec2::254" ascii
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

rule env_dump
{
  meta:
    tier = "weak"
    scope = "code"
    eco = "both"
    summary = "The whole environment is copied into one object or string."
  strings:
    $j = "JSON.stringify" ascii
    $env = "\x70rocess.env" ascii
    $ent = "Object.entries" ascii
    $keys = "Object.keys" ascii
    $dict = "dict(" ascii
    $ose = "\x6fs.environ" ascii
    $copy = "os.environ.copy" ascii
    $spread = "...process.env" ascii
  condition:
    (
      for any i in (1 .. #j) : (
        $env in (@j[i] .. @j[i] + 36)
      )
    ) or (
      for any i in (1 .. #ent) : (
        $env in (@ent[i] .. @ent[i] + 40)
      )
    ) or (
      for any i in (1 .. #keys) : (
        $env in (@keys[i] .. @keys[i] + 40)
      )
    ) or (
      for any i in (1 .. #dict) : (
        $ose in (@dict[i] .. @dict[i] + 24)
      )
    ) or
    $copy or
    $spread
}

rule env_dump_send
{
  meta:
    tier = "weak"
    scope = "code"
    eco = "both"
    summary = "The whole environment is copied and a network call is made in the same added code."
  strings:
    $j = "JSON.stringify" ascii
    $env = "\x70rocess.env" ascii
    $ent = "Object.entries" ascii
    $keys = "Object.keys" ascii
    $dict = "dict(" ascii
    $ose = "\x6fs.environ" ascii
    $copy = "os.environ.copy" ascii
    $n1 = "\x66etch(" ascii
    $n2 = "\x68ttp.request" ascii
    $n3 = "\x68ttps.request" ascii
    $n4 = "http.get" ascii
    $n5 = "https.get" ascii
    $n6 = "axios" ascii
    $n7 = "requests.post" ascii
    $n8 = "requests.get" ascii
    $n9 = "requests.put" ascii
    $n10 = "urlopen" ascii
    $n11 = "urllib.request" ascii
  condition:
    (
      (
        for any i in (1 .. #j) : (
          $env in (@j[i] .. @j[i] + 36)
        )
      ) or (
        for any i in (1 .. #ent) : (
          $env in (@ent[i] .. @ent[i] + 36)
        )
      ) or (
        for any i in (1 .. #keys) : (
          $env in (@keys[i] .. @keys[i] + 36)
        )
      ) or (
        for any i in (1 .. #dict) : (
          $ose in (@dict[i] .. @dict[i] + 24)
        )
      ) or
      $copy
    ) and (
      $n1 or $n2 or $n3 or $n4 or $n5 or $n6 or $n7 or $n8 or $n9 or $n10 or $n11
    )
}

rule npm_hook_beacon
{
  meta:
    tier = "weak"
    scope = "npm_manifest"
    eco = "npm"
    summary = "A package script sends the user or host name out, or looks up a name built from a variable."
  strings:
    $who = "$(whoami" ascii
    $host = "$(hostname" ascii
    $id = "$(id" ascii
    $un = "$(uname" ascii
    $curl = "curl " ascii
    $wget = "wget " ascii
    $user = "$USER" ascii
    $hn = "$HOSTNAME" ascii
    $home = "$HOME" ascii
    $pkg = "$npm_package_name" ascii
    $pwd = "$PWD" ascii
    $look = "nslookup" ascii
    $look2 = "dig " ascii
  condition:
    $who or
    $host or
    $id or
    $un or
    (
      for any i in (1 .. #look) : (
        @look[i] + 70 < filesize and
        for any k in (0 .. 50) : (
          uint8(@look[i] + 8 + k) == 0x24
        )
      )
    ) or
    (
      for any i in (1 .. #look2) : (
        @look2[i] + 66 < filesize and
        for any k in (0 .. 50) : (
          uint8(@look2[i] + 4 + k) == 0x24
        )
      )
    ) or
    (
      ($curl or $wget) and ($user or $hn or $home or $pkg or $pwd)
    )
}

rule curl_upload_secret
{
  meta:
    tier = "weak"
    scope = "code,manifest,workflow"
    eco = "both"
    summary = "curl uploads a key file or a credentials file."
  strings:
    $curl = "curl " ascii
    $up1 = "-T " ascii
    $up2 = "--upload-file" ascii
    $up3 = "-d @" ascii
    $up4 = "--data-binary" ascii
    $up5 = "-F " ascii
    $s1 = ".ssh\x2f" ascii
    $s2 = "\x69d_rsa" ascii
    $s3 = ".\x6epmrc" ascii
    $s4 = ".aws\x2fcredentials" ascii
    $s5 = ".\x70ypirc" ascii
    $s6 = ".netrc" ascii
    $s7 = ".git-credentials" ascii
  condition:
    for any i in (1 .. #curl) : (
      (
        $up1 in (@curl[i] .. @curl[i] + 200) or
        $up2 in (@curl[i] .. @curl[i] + 200) or
        $up3 in (@curl[i] .. @curl[i] + 200) or
        $up4 in (@curl[i] .. @curl[i] + 200) or
        $up5 in (@curl[i] .. @curl[i] + 200)
      ) and (
        $s1 in (@curl[i] .. @curl[i] + 260) or
        $s2 in (@curl[i] .. @curl[i] + 260) or
        $s3 in (@curl[i] .. @curl[i] + 260) or
        $s4 in (@curl[i] .. @curl[i] + 260) or
        $s5 in (@curl[i] .. @curl[i] + 260) or
        $s6 in (@curl[i] .. @curl[i] + 260) or
        $s7 in (@curl[i] .. @curl[i] + 260)
      )
    )
}
