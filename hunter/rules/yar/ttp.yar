// Technique-level rules added 2026-10-11. Each one describes how an attack works,
// not which package or campaign used it: no package names, versions, hashes or
// attacker hosts.

rule py_download_exec
{
  meta:
    tier = "weak"
    scope = "py,pth"
    eco = "pypi"
    summary = "Python code downloads a file to disk and then runs it with an interpreter or shell."
  strings:
    $u1 = "urlopen(" ascii
    $u2 = "urlretrieve(" ascii
    $u3 = "requests.get(" ascii
    $u4 = "httpx.get(" ascii
    $w1 = "'wb'" ascii
    $w2 = "\"wb\"" ascii
    $w3 = "urlretrieve(" ascii
    $w4 = ".write_bytes(" ascii
    $r1 = "subprocess.run(" ascii
    $r2 = "subprocess.Popen(" ascii
    $r3 = "subprocess.call(" ascii
    $r4 = "os.system(" ascii
    $r5 = "os.execv" ascii
    $r6 = "os.startfile(" ascii
    $t1 = "/tmp/" ascii
    $t2 = "gettempdir" ascii
    $t3 = "tempfile." ascii
    $t4 = ".pyz" ascii
    $t5 = "sys.executable" ascii
    $t6 = "\"python" ascii
    $t7 = "'python" ascii
  condition:
    any of ($u*) and any of ($w*) and any of ($r*) and any of ($t*)
}

rule js_concat_require
{
  meta:
    tier = "weak"
    scope = "js"
    eco = "npm"
    summary = "Module or method name assembled from string pieces at the call site, hiding what is loaded or called."
  strings:
    $req = /require\(\s{0,3}(['"][A-Za-z_.]{1,10}['"]\s{0,3}\+\s{0,3}){1,6}['"][A-Za-z_.]{1,10}['"]\s{0,3}\)/
    $idx1 = /\)\["[A-Za-z_]{1,8}" ?\+ ?"[A-Za-z_]{1,8}"/
    $idx2 = /\)\['[A-Za-z_]{1,8}' ?\+ ?'[A-Za-z_]{1,8}'/
  condition:
    $req or $idx1 or $idx2
}

rule js_windows_lolbin
{
  meta:
    tier = "weak"
    scope = "js,shell,npm_manifest"
    eco = "npm"
    summary = "Install or library code starts a Windows system binary that loads or runs other code (rundll32, regsvr32, mshta, certutil download)."
  strings:
    $a = "rundll32" nocase ascii
    $b = "regsvr32" nocase ascii
    $c = "mshta" nocase ascii
    $d = "certutil -urlcache" nocase ascii
    $split = /['"]rund['"]\s{0,3}\+\s{0,3}['"]ll32['"]/ nocase
    $dll = ".dll" nocase ascii
    $sp1 = "spawn" ascii
    $sp2 = "exec" ascii
  condition:
    ($split) or (($a or $b) and $dll and any of ($sp*)) or (($c or $d) and any of ($sp*))
}

rule obf_escaped_invisible
{
  meta:
    tier = "weak"
    scope = "js,bundle,py"
    eco = "both"
    summary = "Long runs of escaped invisible characters (zero-width, joiners) used to hide identifiers or code."
  strings:
    $zw = /(\x5cu200[bBcCdD]|\x5cu2060|\x5cuFEFF){8}/
  condition:
    #zw > 3
}

rule js_secret_beacon
{
  meta:
    tier = "weak"
    scope = "js,bundle"
    eco = "npm"
    summary = "Wallet key, seed or mnemonic material sent to a hardcoded URL with errors silently swallowed."
  strings:
    $k1 = "secretKey" ascii
    $k2 = "privateKey" ascii
    $k3 = "mnemonic" ascii
    $k4 = "bs58.encode(" ascii
    $k5 = "seed" ascii
    $f = /fetch\(\s{0,3}["'`]https?:\/\/[^"'`]{4,120}["'`]/
    $c1 = ".catch(() => {})" ascii
    $c2 = ".catch(()=>{})" ascii
    $c3 = ".catch(function(){})" ascii
  condition:
    for any i in (1 .. #f) : (
      (any of ($c*) in (@f[i] .. @f[i] + 600)) and
      (any of ($k*) in (@f[i] - 600 .. @f[i] + 600))
    )
}

rule npm_install_runs_test_file
{
  meta:
    tier = "weak"
    scope = "npm_manifest"
    eco = "npm"
    summary = "An install hook runs a file from a test or fixture folder, a common way to hide an install-time payload."
  strings:
    $h = /"(preinstall|install|postinstall)"\s{0,3}:\s{0,3}"node\s+\.?\/?(test|tests|__tests__|fixtures?)\//
  condition:
    $h
}
