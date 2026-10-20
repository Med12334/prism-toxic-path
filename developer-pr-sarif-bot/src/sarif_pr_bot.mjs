/**
 * Delivers accurate, prioritized findings directly inside the tools developers already use:
 * 1. Filters out non-reachable P4 noise so developers only see exploitable findings.
 * 2. Generates official GitHub Code Scanning SARIF v2.1.0 output.
 * 3. Formats one-click GitHub Pull Request ```suggestion blocks for instant remediation.
 */
export function buildDeveloperPrFeedback(findings) {
  const actionable = findings.filter((f) => f.reachable && f.toxicScore >= 70.0);
  const suppressedNoiseCount = findings.length - actionable.length;

  const sarifReport = {
    $schema: '[https://json.schemastore.org/sarif-2.1.0.json](https://json.schemastore.org/sarif-2.1.0.json)',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Prism-Toxic-Path (Wiz + AST Reachability Engine)',
            version: '1.0.0'
          }
        },
        results: actionable.map((item) => ({
          ruleId: item.ruleId,
          level: 'error',
          message: {
            text: `[TOXIC SCORE ${item.toxicScore}] ${item.summary} \vert{} Attack Path:${item.attackPath.join(' -> ')}`
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: item.filePath },
                region: { startLine: item.line }
              }
            }
          ]
        }))
      }
    ]
  };

  const prComments = actionable.map((item) => ({
    path: item.filePath,
    line: item.line,
    body: [
      `### 🚨 Prism Toxic Path Blocked Release (\`${item.ruleId}\` — Score: **${item.toxicScore}/100**)`,
      `**Why this matters:** ${item.summary}`,
      `**Verified Attack Path:** \`${item.attackPath.join(' -> ')}\``,
      '',
      '**One-Click Developer Fix:**',
      '```suggestion',
      item.suggestedFixLine,
      '```'
    ].join('\n')
  }));

  return {
    actionableCount: actionable.length,
    suppressedNoiseCount,
    sarifReport,
    prComments
  };
}
