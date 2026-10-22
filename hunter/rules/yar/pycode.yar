// Python packaging and decoded execution.

rule py_exec_decoded
{
  meta:
    tier = "weak"
    scope = "py,pth"
    eco = "pypi"
    summary = "exec or eval is handed the result of a decode or decompress call."
  strings:
    $exec = "exec(" ascii
    $eval = "\x65val(" ascii
    $m = "marshal.loads" ascii
    $z = "zlib.decompress" ascii
    $l = "lzma.decompress" ascii
    $b = "bz2.decompress" ascii
    $b64 = "b64decode" ascii
    $b32 = "b32decode" ascii
    $b85 = "b85decode" ascii
    $b16 = "b16decode" ascii
    $a85 = "a85decode" ascii
    $codecs = "codecs.decode" ascii
    $hex = "bytes.fromhex" ascii
    $a2b = "a2b_base64" ascii
    $imp = "\x5f_import__(" ascii
  condition:
    (
      for any i in (1 .. #exec) : (
        $m in (@exec[i] .. @exec[i] + 40) or
        $z in (@exec[i] .. @exec[i] + 40) or
        $l in (@exec[i] .. @exec[i] + 40) or
        $b in (@exec[i] .. @exec[i] + 40) or
        $b64 in (@exec[i] .. @exec[i] + 48) or
        $b32 in (@exec[i] .. @exec[i] + 48) or
        $b85 in (@exec[i] .. @exec[i] + 48) or
        $b16 in (@exec[i] .. @exec[i] + 48) or
        $a85 in (@exec[i] .. @exec[i] + 48) or
        $codecs in (@exec[i] .. @exec[i] + 40) or
        $hex in (@exec[i] .. @exec[i] + 40) or
        $a2b in (@exec[i] .. @exec[i] + 48) or
        $imp in (@exec[i] .. @exec[i] + 24)
      )
    ) or (
      for any i in (1 .. #eval) : (
        $m in (@eval[i] .. @eval[i] + 40) or
        $z in (@eval[i] .. @eval[i] + 40) or
        $l in (@eval[i] .. @eval[i] + 40) or
        $b64 in (@eval[i] .. @eval[i] + 48) or
        $codecs in (@eval[i] .. @eval[i] + 40) or
        $hex in (@eval[i] .. @eval[i] + 40) or
        $imp in (@eval[i] .. @eval[i] + 24)
      )
    )
}

rule py_chr_exec
{
  meta:
    tier = "weak"
    scope = "py,pth"
    eco = "pypi"
    summary = "exec or eval runs a string built from chr() calls."
  strings:
    $exec = "exec(" ascii
    $eval = "\x65val(" ascii
    $join = ".join(" ascii
    $chr = "chr" ascii
    $plus = "+ chr" ascii
  condition:
    (
      for any i in (1 .. #exec) : (
        (
          $join in (@exec[i] .. @exec[i] + 24) and
          $chr in (@exec[i] .. @exec[i] + 48)
        ) or
        $plus in (@exec[i] .. @exec[i] + 28)
      )
    ) or (
      for any i in (1 .. #eval) : (
        (
          $join in (@eval[i] .. @eval[i] + 24) and
          $chr in (@eval[i] .. @eval[i] + 48)
        ) or
        $plus in (@eval[i] .. @eval[i] + 28)
      )
    )
}

rule py_import_alias_exec
{
  meta:
    tier = "weak"
    scope = "py,pth"
    eco = "pypi"
    summary = "A shell or exec builtin is reached through __import__ or a renamed import."
  strings:
    $imp = "\x5f_import__(" ascii
    $os = "'os'" ascii
    $os2 = "\"os\"" ascii
    $bi = "'builtins'" ascii
    $bi2 = "\"builtins\"" ascii
    $sub = "'subprocess'" ascii
    $sub2 = "\"subprocess\"" ascii
    $system = ".system" ascii
    $popen = ".popen" ascii
    $Popen = ".Popen" ascii
    $run = ".run" ascii
    $exec = ".exec" ascii
    $from = "from " ascii
    $as = " as " ascii
  condition:
    (
      for any i in (1 .. #imp) : (
        (
          $os in (@imp[i] .. @imp[i] + 20) or
          $os2 in (@imp[i] .. @imp[i] + 20) or
          $bi in (@imp[i] .. @imp[i] + 24) or
          $bi2 in (@imp[i] .. @imp[i] + 24) or
          $sub in (@imp[i] .. @imp[i] + 28) or
          $sub2 in (@imp[i] .. @imp[i] + 28)
        ) and (
          $system in (@imp[i] .. @imp[i] + 40) or
          $popen in (@imp[i] .. @imp[i] + 40) or
          $Popen in (@imp[i] .. @imp[i] + 40) or
          $run in (@imp[i] .. @imp[i] + 40) or
          $exec in (@imp[i] .. @imp[i] + 40)
        )
      )
    ) or (
      for any i in (1 .. #from) : (
        $as in (@from[i] .. @from[i] + 48) and
        (
          $system in (@from[i] .. @from[i] + 40) or
          $Popen in (@from[i] .. @from[i] + 40) or
          $exec in (@from[i] .. @from[i] + 40) or
          $popen in (@from[i] .. @from[i] + 40)
        )
      )
    )
}

rule py_dynamic_loader
{
  meta:
    tier = "weak"
    scope = "py"
    eco = "pypi"
    summary = "A module name is decoded and then imported."
  strings:
    $mod = "import_module" ascii
    $imp = "\x5f_import__(" ascii
    $b64 = "b64decode" ascii
    $b64w = "\x62ase64" ascii
    $hex = "fromhex" ascii
    $codecs = "codecs.decode" ascii
  condition:
    (
      for any i in (1 .. #mod) : (
        $b64 in (@mod[i] .. @mod[i] + 120) or
        $b64w in (@mod[i] .. @mod[i] + 120) or
        $hex in (@mod[i] .. @mod[i] + 120) or
        $codecs in (@mod[i] .. @mod[i] + 120)
      )
    ) or (
      for any i in (1 .. #imp) : (
        $b64 in (@imp[i] .. @imp[i] + 120) or
        $b64w in (@imp[i] .. @imp[i] + 120) or
        $hex in (@imp[i] .. @imp[i] + 120) or
        $codecs in (@imp[i] .. @imp[i] + 120)
      )
    )
}

rule py_compile_exec
{
  meta:
    tier = "weak"
    scope = "py"
    eco = "pypi"
    summary = "exec runs code compiled from decoded or downloaded text."
  strings:
    $exec = "exec(" ascii
    $comp = "\x63ompile(" ascii
    $b64 = "b64decode" ascii
    $dec = "decompress" ascii
    $url = "urlopen" ascii
    $get = "requests.get" ascii
    $read = ".read()" ascii
  condition:
    for any i in (1 .. #exec) : (
      $comp in (@exec[i] .. @exec[i] + 16) and
      (
        $b64 in (@exec[i] .. @exec[i] + 170) or
        $dec in (@exec[i] .. @exec[i] + 170) or
        $url in (@exec[i] .. @exec[i] + 170) or
        $get in (@exec[i] .. @exec[i] + 170) or
        $read in (@exec[i] .. @exec[i] + 170)
      )
    )
}

rule setup_net_import
{
  meta:
    tier = "weak"
    scope = "py_manifest"
    eco = "pypi"
    summary = "A setup script imports a library that opens network connections."
  strings:
    $a = "import requests" ascii
    $b = "from requests" ascii
    $c = "import urllib.request" ascii
    $d = "from urllib.request" ascii
    $e = "import urllib2" ascii
    $f = "from urllib2" ascii
    $g = "import http.client" ascii
    $h = "from http.client" ascii
    $i = "import socket" ascii
    $j = "from socket" ascii
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
    ) or
    for any i in (1 .. #e) : (
      @e[i] < filesize and
      @e[i] >= 0 and
      uint8(@e[i]) >= 0x09 and
      uint8(@e[i]) <= 0x7e and
      uint8(@e[i]) != 0x00 and
      uint8(@e[i]) != 0x01 and
      uint8(@e[i]) != 0x02 and
      uint8(@e[i]) != 0x7f and
      not (@e[i] > filesize)
    ) or
    for any i in (1 .. #f) : (
      @f[i] < filesize and
      @f[i] >= 0 and
      uint8(@f[i]) >= 0x09 and
      uint8(@f[i]) <= 0x7e and
      uint8(@f[i]) != 0x00 and
      uint8(@f[i]) != 0x01 and
      uint8(@f[i]) != 0x02 and
      uint8(@f[i]) != 0x7f and
      not (@f[i] > filesize)
    ) or
    for any i in (1 .. #g) : (
      @g[i] < filesize and
      @g[i] >= 0 and
      uint8(@g[i]) >= 0x09 and
      uint8(@g[i]) <= 0x7e and
      uint8(@g[i]) != 0x00 and
      uint8(@g[i]) != 0x01 and
      uint8(@g[i]) != 0x02 and
      uint8(@g[i]) != 0x7f and
      not (@g[i] > filesize)
    ) or
    for any i in (1 .. #h) : (
      @h[i] < filesize and
      @h[i] >= 0 and
      uint8(@h[i]) >= 0x09 and
      uint8(@h[i]) <= 0x7e and
      uint8(@h[i]) != 0x00 and
      uint8(@h[i]) != 0x01 and
      uint8(@h[i]) != 0x02 and
      uint8(@h[i]) != 0x7f and
      not (@h[i] > filesize)
    ) or
    for any i in (1 .. #i) : (
      @i[i] < filesize and
      @i[i] >= 0 and
      uint8(@i[i]) >= 0x09 and
      uint8(@i[i]) <= 0x7e and
      uint8(@i[i]) != 0x00 and
      uint8(@i[i]) != 0x01 and
      uint8(@i[i]) != 0x02 and
      uint8(@i[i]) != 0x7f and
      not (@i[i] > filesize)
    ) or
    for any i in (1 .. #j) : (
      @j[i] < filesize and
      @j[i] >= 0 and
      uint8(@j[i]) >= 0x09 and
      uint8(@j[i]) <= 0x7e and
      uint8(@j[i]) != 0x00 and
      uint8(@j[i]) != 0x01 and
      uint8(@j[i]) != 0x02 and
      uint8(@j[i]) != 0x7f and
      not (@j[i] > filesize)
    )
}

rule setup_ctypes_pty
{
  meta:
    tier = "weak"
    scope = "py_manifest"
    eco = "pypi"
    summary = "A setup script loads a native library or opens a terminal."
  strings:
    $a = "ctypes.CDLL" ascii
    $b = "ctypes.WinDLL" ascii
    $c = "ctypes.windll" ascii
    $d = "ctypes.cdll" ascii
    $e = "pty.spawn" ascii
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
    ) or
    for any i in (1 .. #e) : (
      @e[i] < filesize and
      @e[i] >= 0 and
      uint8(@e[i]) >= 0x09 and
      uint8(@e[i]) <= 0x7e and
      uint8(@e[i]) != 0x00 and
      uint8(@e[i]) != 0x01 and
      uint8(@e[i]) != 0x02 and
      uint8(@e[i]) != 0x7f and
      not (@e[i] > filesize)
    )
}

rule pth_exec_line
{
  meta:
    tier = "weak"
    scope = "pth"
    eco = "pypi"
    summary = "A path configuration line imports a module and then runs code."
  strings:
    $imp = "import " ascii
    $exec = "\x65xec" ascii
    $eval = "eval" ascii
    $sub = "subprocess" ascii
    $b64 = "\x62ase64" ascii
    $url = "urllib" ascii
    $sock = "\x73ocket" ascii
    $sys = "os.system" ascii
    $call = "\x5f_import__" ascii
    $comp = "compile" ascii
  condition:
    for any i in (1 .. #imp) : (
      $exec in (@imp[i] .. @imp[i] + 400) or
      $eval in (@imp[i] .. @imp[i] + 400) or
      $sub in (@imp[i] .. @imp[i] + 400) or
      $b64 in (@imp[i] .. @imp[i] + 400) or
      $url in (@imp[i] .. @imp[i] + 400) or
      $sock in (@imp[i] .. @imp[i] + 400) or
      $sys in (@imp[i] .. @imp[i] + 400) or
      $call in (@imp[i] .. @imp[i] + 400) or
      $comp in (@imp[i] .. @imp[i] + 400)
    )
}

rule pyproject_backend_path
{
  meta:
    tier = "weak"
    scope = "py_manifest"
    eco = "pypi"
    summary = "The build backend is pointed at code shipped inside the package."
  strings:
    $key = "\x62ackend-path" ascii
  condition:
    for any i in (1 .. #key) : (
      @key[i] + 12 < filesize and
      (
        uint8(@key[i] + 12) == 0x3d or
        (
          (uint8(@key[i] + 12) == 0x20 or uint8(@key[i] + 12) == 0x09) and
          uint8(@key[i] + 13) == 0x3d
        ) or
        (
          (uint8(@key[i] + 12) == 0x20 or uint8(@key[i] + 12) == 0x09) and
          (uint8(@key[i] + 13) == 0x20 or uint8(@key[i] + 13) == 0x09) and
          uint8(@key[i] + 14) == 0x3d
        ) or
        (
          (uint8(@key[i] + 12) == 0x20 or uint8(@key[i] + 12) == 0x09) and
          (uint8(@key[i] + 13) == 0x20 or uint8(@key[i] + 13) == 0x09) and
          (uint8(@key[i] + 14) == 0x20 or uint8(@key[i] + 14) == 0x09) and
          uint8(@key[i] + 15) == 0x3d
        ) or
        (
          (uint8(@key[i] + 12) == 0x20 or uint8(@key[i] + 12) == 0x09) and
          (uint8(@key[i] + 13) == 0x20 or uint8(@key[i] + 13) == 0x09) and
          (uint8(@key[i] + 14) == 0x20 or uint8(@key[i] + 14) == 0x09) and
          (uint8(@key[i] + 15) == 0x20 or uint8(@key[i] + 15) == 0x09) and
          uint8(@key[i] + 16) == 0x3d
        )
      )
    )
}

rule py_daemon_fetch_exec
{
  meta:
    tier = "weak"
    scope = "py"
    eco = "pypi"
    summary = "Python code forks into the background and runs code it downloads."
  strings:
    $fork = "os.fork(" ascii
    $setsid = "os.setsid(" ascii
    $urlopen = "urlopen(" ascii
    $req = "requests.get(" ascii
    $client = "HTTPSConnection(" ascii
    $exec = "\x65xec(" ascii
  condition:
    ($fork or $setsid) and
    ($urlopen or $req or $client) and
    $exec
}
