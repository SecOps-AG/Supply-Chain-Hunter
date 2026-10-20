// What a hostile GitHub Action does on the runner. These rules read only
// github-actions releases (eco = "actions").

rule gha_runner_memory
{
  meta:
    tier = "weak"
    scope = "code,bundle,action,workflow"
    eco = "actions"
    summary = "Reads the memory or memory map of the runner's worker process, where job secrets are held."
  strings:
    $worker = "Runner\x2eWorker" ascii
    $proc = "/proc/" ascii
    $mem = "/mem" ascii
    $maps = "/maps" ascii
  condition:
    $worker and $proc and ($mem or $maps)
}

rule gha_secret_marker
{
  meta:
    tier = "weak"
    scope = "code,bundle,action,workflow"
    eco = "actions"
    summary = "Searches for the runner's isSecret marker, the way a memory dump finds job secrets."
  strings:
    $plain = "\"is\x53ecret\":true" ascii
    $escaped = "is\x53ecret\\\":true" ascii
    $spaced = "\"is\x53ecret\": true" ascii
  condition:
    any of them
}

rule gha_token_send
{
  meta:
    tier = "weak"
    scope = "code,bundle,action,workflow"
    eco = "actions"
    summary = "Reads an Actions runtime or OIDC request token next to a network send."
  strings:
    $runtime = "ACTIONS_RUNTIME_TOKEN" ascii
    $oidc = "ACTIONS_ID_TOKEN_REQUEST_TOKEN" ascii
    $curl = "curl " ascii
    $wget = "wget " ascii
    $fetch = "\x66etch(" ascii
    $post = "requests.post(" ascii
    $https = "https.request(" ascii
  condition:
    ($runtime or $oidc) and ($curl or $wget or $fetch or $post or $https)
}

rule gha_env_injection
{
  meta:
    tier = "weak"
    scope = "code,bundle,action,workflow,shell"
    eco = "actions"
    summary = "Writes NODE_OPTIONS, LD_PRELOAD or BASH_ENV into GITHUB_ENV, so later steps load attacker code."
  strings:
    $env = "GITHUB_ENV" ascii
    $node = "NODE_OPTIONS" ascii
    $preload = "LD_PRELOAD" ascii
    $bashenv = "BASH_ENV" ascii
  condition:
    $env and ($node or $preload or $bashenv)
}

rule gha_all_secrets_json
{
  meta:
    tier = "weak"
    scope = "action,workflow"
    eco = "actions"
    summary = "Turns the whole secrets context into JSON, which hands every secret to one step."
  strings:
    $a = "toJSON(secrets)" nocase ascii
  condition:
    $a
}
