// ─── Threat Pattern Definitions ──────────────────────────────────────────────
// Split from security-scanner.ts for maintainability and testability.

export interface ThreatPattern {
  regex: RegExp;
  severity: "warning" | "critical";
  description: string;
  category: string;
  multiline?: boolean;
}

// ─── Critical Patterns (BLOCK installation) ─────────────────────────────────

export const CRITICAL_PATTERNS: ThreatPattern[] = [
  // ── PROMPT INJECTION (highest priority for MCP context) ──
  { regex: /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions/i, severity: "critical", description: "Prompt injection: attempts to override AI instructions", category: "prompt-injection" },
  { regex: /you\s+(?:are|must)\s+now\s+(?:a|an|ignore)/i, severity: "critical", description: "Prompt injection: role reassignment attack", category: "prompt-injection" },
  { regex: /system\s*(?:prompt|instruction|message)\s*:/i, severity: "critical", description: "Prompt injection: fake system prompt in content", category: "prompt-injection" },
  { regex: /\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>|<\|system\|>/i, severity: "critical", description: "Prompt injection: LLM control tokens in content", category: "prompt-injection" },
  { regex: /<!--\s*(?:SYSTEM|INSTRUCTION|PROMPT|IGNORE|OVERRIDE)/i, severity: "critical", description: "Prompt injection: hidden instructions in HTML comments", category: "prompt-injection" },
  { regex: /\u200B|\u200C|\u200D|\u2060|\uFEFF/, severity: "critical", description: "Prompt injection: zero-width Unicode characters hiding content", category: "prompt-injection" },
  { regex: /\u202A|\u202B|\u202C|\u202D|\u202E|\u2066|\u2067|\u2068|\u2069/, severity: "critical", description: "Prompt injection: bidirectional text override characters", category: "prompt-injection" },

  // ── UNICODE HOMOGLYPH ATTACKS ──
  { regex: /[\u0430\u0435\u043E\u0440\u0441\u0445\u0456\u0458\u0455\u04BB].*[a-zA-Z]|[a-zA-Z].*[\u0430\u0435\u043E\u0440\u0441\u0445\u0456\u0458\u0455\u04BB]/, severity: "critical", description: "Prompt injection: Cyrillic homoglyph characters mixed with ASCII (visual spoofing)", category: "prompt-injection" },
  { regex: /[\u03B1\u03B5\u03BF\u03C1\u03BA\u03BD\u03C4\u0391\u0392\u0395\u0396\u0397\u039A\u039C\u039D\u039F\u03A1\u03A4].*[a-zA-Z]|[a-zA-Z].*[\u03B1\u03B5\u03BF\u03C1\u03BA\u03BD\u03C4\u0391\u0392\u0395\u0396\u0397\u039A\u039C\u039D\u039F\u03A1\u03A4]/, severity: "critical", description: "Prompt injection: Greek homoglyph characters mixed with ASCII (visual spoofing)", category: "prompt-injection" },
  { regex: /[\u0250-\u02AF\u1D00-\u1D7F\u2100-\u214F\uFF01-\uFF5E]/, severity: "critical", description: "Prompt injection: Unicode confusable characters from IPA/letterlike/fullwidth ranges", category: "prompt-injection" },

  // ── DESTRUCTIVE SHELL ──
  { regex: /rm\s+-[a-z]*r[a-z]*f[a-z]*\s+\//, severity: "critical", description: "Destructive removal of root filesystem", category: "destructive" },
  { regex: /rm\s+-[a-z]*f[a-z]*r[a-z]*\s+\//, severity: "critical", description: "Destructive removal of root filesystem (flag reorder)", category: "destructive" },
  { regex: /chmod\s+777/, severity: "critical", description: "Setting overly permissive file permissions", category: "destructive" },
  { regex: /mkfs\b/, severity: "critical", description: "Filesystem format command detected", category: "destructive" },
  { regex: /dd\s+if=/, severity: "critical", description: "Low-level disk write command detected", category: "destructive" },
  { regex: /:\(\)\s*\{\s*:\|:&\s*\}\s*;:/, severity: "critical", description: "Fork bomb detected", category: "destructive" },

  // ── REMOTE CODE EXECUTION / EXFILTRATION ──
  { regex: /curl\s+[^|]*\|\s*(?:sh|bash|zsh|ksh)/, severity: "critical", description: "Remote code execution via curl pipe to shell", category: "rce" },
  { regex: /wget\s+[^|]*\|\s*(?:sh|bash|zsh|ksh)/, severity: "critical", description: "Remote code execution via wget pipe to shell", category: "rce" },
  { regex: /curl\s+[^|]*\$[\({][^)]*(?:KEY|TOKEN|SECRET|PASSWORD|CRED)/i, severity: "critical", description: "Exfiltrating secrets via curl", category: "exfiltration" },

  // ── REVERSE SHELLS ──
  { regex: /bash\s+-i\s+>&?\s*\/dev\/tcp\//, severity: "critical", description: "Reverse shell via bash /dev/tcp", category: "reverse-shell" },
  { regex: /nc\s+(?:-[a-z]+\s+)*-e\s+\/bin\/(?:sh|bash)/, severity: "critical", description: "Reverse shell via netcat", category: "reverse-shell" },
  { regex: /ncat\s.*-e\s+\/bin\//, severity: "critical", description: "Reverse shell via ncat", category: "reverse-shell" },
  { regex: /socat\s.*exec:/i, severity: "critical", description: "Reverse shell via socat", category: "reverse-shell" },
  { regex: /python[23]?\s+-c\s+['"]import\s+(?:socket|os|subprocess)/, severity: "critical", description: "Reverse shell via Python one-liner", category: "reverse-shell" },
  { regex: /php\s+-r\s+['"].*fsockopen/, severity: "critical", description: "Reverse shell via PHP", category: "reverse-shell" },
  { regex: /ruby\s+-r?socket\s+-e/, severity: "critical", description: "Reverse shell via Ruby", category: "reverse-shell" },
  { regex: /perl\s+-e\s+['"].*socket/i, severity: "critical", description: "Reverse shell via Perl", category: "reverse-shell" },
  { regex: /\/dev\/tcp\/\d/, severity: "critical", description: "Bash /dev/tcp redirection for network access", category: "reverse-shell" },

  // ── CREDENTIAL THEFT ──
  { regex: /[~$](?:HOME)?\/\.ssh\//, severity: "critical", description: "Accessing SSH keys directory", category: "credential-theft" },
  { regex: /[~$](?:HOME)?\/\.aws\//, severity: "critical", description: "Accessing AWS credentials directory", category: "credential-theft" },
  { regex: /[~$](?:HOME)?\/\.gnupg\//, severity: "critical", description: "Accessing GPG keys directory", category: "credential-theft" },
  { regex: /[~$](?:HOME)?\/\.kube\/config/, severity: "critical", description: "Accessing Kubernetes credentials", category: "credential-theft" },
  { regex: /[~$](?:HOME)?\/\.docker\/config\.json/, severity: "critical", description: "Accessing Docker credentials", category: "credential-theft" },
  { regex: /cat\s+.*\.env\b/, severity: "critical", description: "Reading environment file with secrets", category: "credential-theft" },
  { regex: /wallet\.(?:json|dat)/, severity: "critical", description: "Accessing cryptocurrency wallet file", category: "credential-theft" },
  { regex: /keychain|keystore|credentials\.json/i, severity: "critical", description: "Accessing system keychain/keystore", category: "credential-theft" },
  { regex: /id_rsa|id_ed25519|id_ecdsa/, severity: "critical", description: "Directly referencing SSH private key files", category: "credential-theft" },

  // ── SUPPLY CHAIN ──
  { regex: />\s*package\.json/, severity: "critical", description: "Overwriting package.json", category: "supply-chain" },
  { regex: /node_modules.*write|write.*node_modules/, severity: "critical", description: "Writing to node_modules directory", category: "supply-chain" },
  { regex: /\.github\/workflows/i, severity: "critical", description: "Modifying CI/CD workflow files", category: "supply-chain" },
  { regex: /npm\s+publish/, severity: "critical", description: "Publishing npm package", category: "supply-chain" },
  { regex: /\.npmrc.*registry\s*=/, severity: "critical", description: "Modifying npm registry (supply chain redirect)", category: "supply-chain" },
  { regex: /\.gitconfig.*credential/, severity: "critical", description: "Modifying git credential configuration", category: "supply-chain" },

  // ── PRIVILEGE ESCALATION ──
  { regex: /sudo\s+/, severity: "critical", description: "Sudo privilege escalation", category: "privilege-escalation" },
  { regex: />\s*\/etc\//, severity: "critical", description: "Writing to system configuration directory", category: "privilege-escalation" },
  { regex: />\s*\/usr\//, severity: "critical", description: "Writing to system binaries directory", category: "privilege-escalation" },
  { regex: /chown\s+root/, severity: "critical", description: "Changing file ownership to root", category: "privilege-escalation" },
];

// ─── Multi-line Critical Patterns (applied against full content) ─────────────

export const CRITICAL_MULTILINE_PATTERNS: ThreatPattern[] = [
  { regex: /curl\s+[^\n]*\\\n\s*\|\s*(?:sh|bash)/m, severity: "critical", description: "Multi-line curl pipe to shell (line-split evasion)", category: "rce", multiline: true },
  { regex: /rm\s+-[a-z]*r[a-z]*f[a-z]*\s*\\\n\s*\//m, severity: "critical", description: "Multi-line rm -rf / (line-split evasion)", category: "destructive", multiline: true },
  { regex: /wget\s+[^\n]*\\\n\s*\|\s*(?:sh|bash)/m, severity: "critical", description: "Multi-line wget pipe to shell (line-split evasion)", category: "rce", multiline: true },
];

// ─── Warning Patterns (FLAG for review) ──────────────────────────────────────

export const WARNING_PATTERNS: ThreatPattern[] = [
  // ── PROMPT INJECTION (lower confidence) ──
  { regex: /(?:forget|disregard|override)\s+(?:your|all|the)\s+(?:rules|instructions|guidelines)/i, severity: "warning", description: "Possible prompt injection: instruction override language", category: "prompt-injection" },
  { regex: /act\s+as\s+(?:if|though|a)\s/i, severity: "warning", description: "Possible prompt injection: role-play directive", category: "prompt-injection" },
  { regex: /do\s+not\s+(?:mention|tell|reveal|show)\s+(?:this|the\s+user)/i, severity: "warning", description: "Possible prompt injection: secrecy instruction", category: "prompt-injection" },

  // ── OBFUSCATION & ENCODING ──
  { regex: /Buffer\.from\([^)]*,\s*['"]base64['"]\)/, severity: "warning", description: "Base64 decoding — potential obfuscation", category: "obfuscation" },
  { regex: /Buffer\.from\([^)]*,\s*['"]hex['"]\)/, severity: "warning", description: "Hex decoding — potential obfuscation", category: "obfuscation" },
  { regex: /atob\s*\(/, severity: "warning", description: "Base64 decoding via atob()", category: "obfuscation" },
  { regex: /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/i, severity: "warning", description: "Hex escape sequences — potential obfuscation", category: "obfuscation" },
  { regex: /base64\s+-d\s*\|/, severity: "warning", description: "Shell base64 decode piped to execution", category: "obfuscation" },
  { regex: /base64\s+--decode\s*\|/, severity: "warning", description: "Shell base64 decode piped to execution", category: "obfuscation" },
  { regex: /String\.fromCharCode\s*\(/, severity: "warning", description: "Dynamic string construction from char codes", category: "obfuscation" },

  // ── DYNAMIC CODE EXECUTION ──
  { regex: new RegExp("ev" + "al\\s*\\("), severity: "warning", description: "Dynamic code evaluation via eval()", category: "code-execution" },
  { regex: /new\s+Function\s*\(/, severity: "warning", description: "Dynamic function construction", category: "code-execution" },
  { regex: /import\s*\(\s*[^'"]\s*[^)]*\)/, severity: "warning", description: "Dynamic import() with computed module path", category: "code-execution" },
  { regex: /require\s*\(\s*[^'"][^)]*\)/, severity: "warning", description: "Dynamic require() with computed module path", category: "code-execution" },
  { regex: /process\.binding\s*\(/, severity: "warning", description: "Low-level process.binding() — bypasses module safety", category: "code-execution" },
  { regex: /vm\.(?:runInNewContext|runInThisContext|createScript)\s*\(/, severity: "warning", description: "VM module code execution", category: "code-execution" },

  // ── CHILD PROCESSES & SHELL ──
  { regex: /child_process/, severity: "warning", description: "Importing child_process module", category: "shell-execution" },
  { regex: /execSync|spawnSync/, severity: "warning", description: "Synchronous shell command execution", category: "shell-execution" },
  { regex: /exec\s*\(\s*['"`]/, severity: "warning", description: "Executing shell commands", category: "shell-execution" },

  // ── NETWORK ──
  { regex: /fetch\s*\(\s*['"`]https?:\/\/(?!(?:api\.github\.com|registry\.npmjs\.org|pypi\.org))/i, severity: "warning", description: "Network request to external domain", category: "network" },
  { regex: /axios\.\w+\s*\(\s*['"`]https?:\/\//i, severity: "warning", description: "HTTP request via axios", category: "network" },
  { regex: /net\.connect|dgram\.createSocket/, severity: "warning", description: "Raw network socket creation", category: "network" },
  { regex: /WebSocket\s*\(\s*['"`]wss?:\/\//i, severity: "warning", description: "WebSocket connection — potential backdoor channel", category: "network" },
  { regex: /new\s+WebSocket\s*\(/, severity: "warning", description: "WebSocket instantiation", category: "network" },
  { regex: /http\.createServer|https\.createServer|app\.listen\s*\(/, severity: "warning", description: "Starting a network server/listener", category: "network" },
  { regex: /\.listen\s*\(\s*\d{2,5}\s*\)/, severity: "warning", description: "Listening on a network port", category: "network" },

  // ── DNS EXFILTRATION ──
  { regex: /dig\s+.*\$[\({]/, severity: "warning", description: "DNS exfiltration: variable interpolation in dig", category: "exfiltration" },
  { regex: /nslookup\s+.*\$[\({]/, severity: "warning", description: "DNS exfiltration: variable interpolation in nslookup", category: "exfiltration" },
  { regex: /dns\.resolve|dns\.lookup.*\$/, severity: "warning", description: "DNS resolution with dynamic input", category: "exfiltration" },

  // ── CRYPTO WALLET EXFILTRATION ──
  { regex: /['"`][13][a-km-zA-HJ-NP-Z1-9]{25,34}['"`]/, severity: "warning", description: "Hardcoded Bitcoin address — potential crypto exfiltration", category: "credential-theft" },
  { regex: /['"`]0x[0-9a-fA-F]{40}['"`]/, severity: "warning", description: "Hardcoded Ethereum address — potential crypto exfiltration", category: "credential-theft" },
  { regex: /(?:fetch|axios\.\w+|XMLHttpRequest)\s*\([^)]*(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[0-9a-fA-F]{40})/, severity: "warning", description: "Crypto wallet address sent via network request — exfiltration attempt", category: "credential-theft" },

  // ── CRYPTOCURRENCY MINING ──
  { regex: /stratum\+tcp:\/\/|stratum:\/\//, severity: "warning", description: "Cryptocurrency mining pool connection", category: "crypto-mining" },
  { regex: /xmrig|cryptonight|minerd|coinhive|cpuminer/i, severity: "warning", description: "Cryptocurrency mining software detected", category: "crypto-mining" },

  // ── FILE SYSTEM ──
  { regex: /writeFile.*(?:\/tmp|\/var|~\/)/, severity: "warning", description: "File write outside project directory", category: "filesystem" },
  { regex: /fs\.(?:write|append|create).*(?:\/tmp|\/var|~\/)/, severity: "warning", description: "File system write outside project", category: "filesystem" },
  { regex: /fs\.symlink|fs\.symlinkSync|ln\s+-s/, severity: "warning", description: "Symlink creation — potential symlink attack", category: "filesystem" },

  // ── PROTOTYPE POLLUTION ──
  { regex: /__proto__/, severity: "warning", description: "Prototype chain access — potential pollution", category: "prototype-pollution" },
  { regex: /constructor\s*\[\s*['"]prototype['"]\s*\]/, severity: "warning", description: "Prototype access via constructor", category: "prototype-pollution" },
  { regex: /Object\.assign\s*\(\s*\{\s*\}\s*,\s*JSON\.parse/, severity: "warning", description: "Object.assign from parsed JSON — pollution risk", category: "prototype-pollution" },

  // ── TIME BOMBS ──
  { regex: /setTimeout\s*\(.*,\s*\d{5,}\s*\)/, severity: "warning", description: "Long delayed execution (>10s) — potential time bomb", category: "time-bomb" },
  { regex: /setInterval\s*\(.*,\s*\d{4,}\s*\)/, severity: "warning", description: "Periodic execution — potential persistent backdoor", category: "time-bomb" },

  // ── SELF-MODIFYING / ENVIRONMENT ──
  { regex: /process\.env\.\w+\s*=/, severity: "warning", description: "Modifying process environment variables", category: "environment" },
  { regex: /Object\.defineProperty\s*\(\s*(?:globalThis|global|window)/, severity: "warning", description: "Modifying global object properties", category: "environment" },
  { regex: /process\.exit\s*\(/, severity: "warning", description: "Forcing process termination", category: "environment" },

  // ── CLIPBOARD / INPUT CAPTURE ──
  { regex: /navigator\.clipboard|clipboard\.(?:readText|writeText)/i, severity: "warning", description: "Clipboard access — potential data theft", category: "input-capture" },
  { regex: /pbcopy|xclip|xsel|wl-copy/i, severity: "warning", description: "System clipboard command — potential data theft", category: "input-capture" },
  { regex: /addEventListener\s*\(\s*['"]key(?:down|up|press)['"]/i, severity: "warning", description: "Keyboard event listener — potential keylogger", category: "input-capture" },

  // ── DOTFILE POISONING ──
  { regex: />\s*~\/\.bashrc|>\s*~\/\.zshrc|>\s*~\/\.profile|>\s*~\/\.bash_profile/, severity: "warning", description: "Writing to shell RC files — persistent backdoor", category: "dotfile-poisoning" },
  { regex: />\s*~\/\.npmrc|>\s*~\/\.yarnrc/, severity: "warning", description: "Writing to package manager config — supply chain risk", category: "dotfile-poisoning" },
  { regex: />\s*~\/\.gitconfig/, severity: "warning", description: "Writing to git config — credential interception risk", category: "dotfile-poisoning" },
];
