package claude

import (
	"fmt"

	shield "github.com/cipher-oss/cipher-shield/internal"
)

// buildPrompt constructs the analysis prompt for Claude Opus.
// The prompt asks Claude to reason about whether the package is malicious
// and return a structured JSON verdict.
func buildPrompt(pkg shield.PackageRef, installScripts map[string]string, sourceSnippets []sourceSnippet) string {
	scriptsSection := ""
	if len(installScripts) > 0 {
		scriptsSection = "\n## Install Scripts\n"
		for hook, cmd := range installScripts {
			scriptsSection += fmt.Sprintf("\n**%s:**\n```\n%s\n```\n", hook, cmd)
		}
	}

	snippetsSection := ""
	if len(sourceSnippets) > 0 {
		snippetsSection = "\n## Suspicious Source File Excerpts\n"
		for _, s := range sourceSnippets {
			snippetsSection += fmt.Sprintf("\n**%s:**\n```\n%s\n```\n", s.path, s.content)
		}
	}

	return fmt.Sprintf(`You are a package security expert analyzing a %s package for malicious behavior.

## Package
- Name: %s
- Version: %s
- Ecosystem: %s
%s%s

## Your Task
Analyze the provided code for signs of malicious behavior. Focus on:
1. **Data exfiltration** — does the code read sensitive data (env vars, credentials, files) and send it externally?
2. **Remote code execution** — does the code download and execute code from the internet?
3. **Persistence** — does the code install anything that survives package removal?
4. **Obfuscation** — is the code unnecessarily obfuscated to hide its behavior?
5. **Supply chain attack patterns** — typosquatting, dependency confusion, maintainer takeover indicators

## Response Format
Respond ONLY with a valid JSON object. No markdown, no explanation outside the JSON:

{
  "malice_score": <integer 0-100>,
  "verdict": "<allow|warn|block>",
  "reasoning": "<2-3 sentence explanation of your conclusion>",
  "findings": [
    {
      "type": "claude",
      "severity": "<critical|high|medium|low|info>",
      "title": "<short title>",
      "description": "<detailed description>"
    }
  ]
}

Rules for verdict:
- "block" if malice_score >= 70 OR you found clear evidence of data exfiltration, RCE, or supply chain attack
- "warn" if malice_score >= 30 OR you found suspicious but ambiguous patterns
- "allow" if malice_score < 30 AND no clear malicious intent

If you found nothing suspicious, return malice_score: 0, verdict: "allow", findings: []`,
		pkg.Ecosystem, pkg.Name, pkg.Version, pkg.Ecosystem,
		scriptsSection, snippetsSection)
}

type sourceSnippet struct {
	path    string
	content string
}
