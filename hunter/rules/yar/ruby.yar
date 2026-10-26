// Ruby library code and gem install hooks. Text only; nothing here is run.

rule rb_eval_fetch
{
  meta:
    tier = "weak"
    scope = "rb"
    eco = "rubygems"
    summary = "eval, instance_eval, or class_eval is handed the result of an HTTP fetch."
  strings:
    $eval = "eval(" ascii
    $net = "Net::HTTP" ascii
    $uri_open = "URI.open" ascii
    $open_uri = "open-uri" ascii
    $open_http = "open(\"http" ascii
    $open_https = "open(\"https" ascii
    $open_http_s = "open('http" ascii
    $open_https_s = "open('https" ascii
  condition:
    for any i in (1 .. #eval) : (
      $net in (@eval[i] .. @eval[i] + 160) or
      $uri_open in (@eval[i] .. @eval[i] + 160) or
      $open_uri in (@eval[i] .. @eval[i] + 160) or
      $open_http in (@eval[i] .. @eval[i] + 80) or
      $open_https in (@eval[i] .. @eval[i] + 80) or
      $open_http_s in (@eval[i] .. @eval[i] + 80) or
      $open_https_s in (@eval[i] .. @eval[i] + 80)
    )
}

rule rb_extconf_fetch
{
  meta:
    tier = "weak"
    scope = "gem_hook"
    eco = "rubygems"
    summary = "An install extension fetches a URL or pipes curl or wget into a shell."
  strings:
    $curl = "curl" ascii
    $wget = "wget" ascii
    $pipe = "| sh" ascii
    $pipe_tight = "|sh" ascii
    $http = "http://" ascii
    $https = "https://" ascii
    $net = "Net::HTTP" ascii
    $uri_open = "URI.open" ascii
    $open_uri = "open-uri" ascii
    $open_http = "open(\"http" ascii
    $open_https = "open(\"https" ascii
    $open_http_s = "open('http" ascii
    $open_https_s = "open('https" ascii
  condition:
    (
      for any i in (1 .. #curl) : (
        $pipe in (@curl[i] .. @curl[i] + 220) or
        $pipe_tight in (@curl[i] .. @curl[i] + 220) or
        $http in (@curl[i] .. @curl[i] + 220) or
        $https in (@curl[i] .. @curl[i] + 220)
      )
    ) or (
      for any i in (1 .. #wget) : (
        $pipe in (@wget[i] .. @wget[i] + 220) or
        $pipe_tight in (@wget[i] .. @wget[i] + 220) or
        $http in (@wget[i] .. @wget[i] + 220) or
        $https in (@wget[i] .. @wget[i] + 220)
      )
    ) or
    $net or $uri_open or $open_uri or $open_http or $open_https or $open_http_s or $open_https_s
}
