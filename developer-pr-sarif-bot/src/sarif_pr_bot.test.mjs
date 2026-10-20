import test from 'node:test';
import assert from 'node:assert/strict';
import { buildDeveloperPrFeedback } from './sarif_pr_bot.mjs';

test('Developer PR SARIF Bot suppresses unreachable CVE noise and emits one-click PR fix suggestions', () => {
  const rawFindings = [
    {
      ruleId: 'CVE-2026-4401',
      filePath: 'src/api/ingest.py',
      line: 42,
      reachable: true,
      toxicScore: 98.0,
      summary: 'Reachable pyyaml.unsafe_load on internet-exposed Wiz pod with IAM Admin role',
      attackPath: ['api_ingest_manifest', 'pyyaml.unsafe_load', 'WIZ_INTERNET_INGRESS', 'WIZ_IAM_ADMIN'],
      suggestedFixLine: '    return pyyaml.safe_load(raw_text)'
    },
    {
      ruleId: 'CVE-2026-9999',
      filePath: 'requirements.txt',
      line: 12,
      reachable: false,
      toxicScore: 14.0,
      summary: 'Transitive dependency never imported or called in service',
      attackPath: ['UNREACHABLE_DEAD_CODE'],
      suggestedFixLine: ''
    }
  ];

  const output = buildDeveloperPrFeedback(rawFindings);
  assert.equal(output.actionableCount, 1);
  assert.equal(output.suppressedNoiseCount, 1);
  assert.equal(output.sarifReport.version, '2.1.0');
  assert.equal(output.sarifReport.runs[0].results.length, 1);
  assert.ok(output.prComments[0].body.includes('```suggestion'));
  assert.ok(output.prComments[0].body.includes('pyyaml.safe_load(raw_text)'));
});
