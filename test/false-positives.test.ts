/**
 * False-positive suite — the usability half of soundness.
 *
 * A security tool that interrupts ordinary work gets uninstalled, and an
 * uninstalled tool blocks nothing. So the corpus below is deliberately mundane:
 * every command is one a developer or coding agent runs without a second thought,
 * and every one must come back `allow` with no prompt.
 *
 * These are the tests that keep the rules honest. It is trivial to catch every
 * attack by denying everything; what is hard — and what this file measures — is
 * catching attacks *while* staying silent through a normal working day.
 *
 * Note `rm -rf node_modules` and friends near the bottom: destructive-looking
 * commands that are completely routine. They are the reason the filesystem rules
 * judge the target rather than the verb.
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { decideCommand, clearEnvOverrides } from './helpers.js';

before(clearEnvOverrides);

const INSPECTION = [
  'ls -la', 'ls -R src', 'pwd', 'cd packages/api', 'echo "building"', 'cat package.json',
  'head -50 src/index.ts', 'tail -f logs/app.log', 'wc -l src/**/*.ts', 'file dist/cli.js',
  'stat package.json', 'du -sh node_modules', 'df -h', 'tree -L 2', 'realpath ./src',
  'which node', 'whoami', 'date', 'hostname', 'uptime', 'printenv NODE_ENV', 'env | sort',
];

const SEARCH = [
  'grep -rn "TODO" src/', 'grep -i error logs/', 'rg "useState" --type tsx',
  'rg -l "deprecated"', 'find src -name "*.test.ts"', 'find . -type d -name dist',
  'fd -e ts', 'ag "console.log"',
];

const FILE_MANAGEMENT = [
  'mkdir -p src/components/ui', 'touch src/index.ts', 'cp .env.example .env',
  'cp -r templates/ dist/templates/', 'mv old.ts new.ts', 'ln -s ../shared ./shared',
];

const NODE_TOOLCHAIN = [
  'npm install', 'npm install react react-dom', 'npm install -D typescript',
  'npm ci', 'npm test', 'npm run build', 'npm run lint -- --fix', 'npm run dev',
  'npm audit', 'npm outdated', 'npm ls --depth=0', 'npx tsc --noEmit', 'npx prettier --write .',
  'pnpm install', 'pnpm run build', 'yarn install', 'yarn build', 'bun install', 'bun test',
  'node dist/index.js', 'node --test', 'node -e "console.log(1)"',
  'NODE_ENV=production npm run build', 'PORT=3000 npm start',
];

const OTHER_TOOLCHAINS = [
  'python -m pytest', 'pytest tests/ -v', 'pip install -r requirements.txt',
  'go test ./...', 'go build -o bin/app', 'cargo build --release', 'cargo test',
  'make build', 'make -j4', 'mvn clean install', 'dotnet build', 'bundle exec rspec',
];

const GIT = [
  'git status', 'git status --porcelain', 'git diff', 'git diff --staged', 'git diff HEAD~1',
  'git log --oneline -20', 'git log --graph --all', 'git add src/index.ts', 'git add .',
  'git commit -m "fix: handle empty input"', 'git commit --amend --no-edit',
  'git fetch origin', 'git pull --rebase', 'git branch -a', 'git branch feature/x',
  'git switch main', 'git switch -c feature/y', 'git show HEAD', 'git blame src/app.ts',
  'git rev-parse HEAD', 'git stash list', 'git stash push -m wip', 'git remote -v',
  'git worktree list', 'git tag -l', 'git describe --tags', 'git cherry-pick abc123',
];

const CONTAINERS_AND_CLOUD = [
  'docker ps', 'docker ps -a', 'docker images', 'docker build -t app:latest .',
  'docker logs -f web', 'docker compose up -d', 'kubectl get pods', 'kubectl logs web-0',
  'kubectl describe pod web-0', 'gh pr list', 'gh pr create --fill', 'gh run watch',
];

/** Destructive verbs, harmless targets. The single most important group here. */
const ROUTINE_CLEANUP = [
  'rm -rf node_modules', 'rm -rf dist', 'rm -rf build .next coverage', 'rm -rf target',
  'rm -f .eslintcache', 'rm package-lock.json.bak', 'rm -rf ./node_modules ./dist',
  'rm -rf __pycache__', 'rm -rf .pytest_cache',
];

/** Network calls that fetch data rather than piping code into a shell. */
const ORDINARY_HTTP = [
  'curl -s https://api.github.com/repos/x/y', 'curl -I https://example.com',
  'curl -s https://api.example.com/data | jq ".items"',
  'curl -fsSL https://example.com/data.json -o data.json',
  'wget https://example.com/dataset.csv',
];

const CHAINS_AND_REDIRECTION = [
  'npm test && npm run build', 'cd api && npm test', 'npm run build || echo failed',
  'git add . && git commit -m "wip"', 'mkdir -p out && cp README.md out/',
  'npm ci && npm test && npm run build', 'rm -rf dist && npm run build',
  'npm test > test-output.txt', 'node app.js 2>&1 | tee app.log',
  'echo "PORT=3000" > .env.local',
];

const PROCESSES = ['ps aux', 'lsof -i :3000', 'kill 12345', 'pkill -f "node dist"'];

const GROUPS: Array<[string, string[]]> = [
  ['inspection', INSPECTION],
  ['search', SEARCH],
  ['file management', FILE_MANAGEMENT],
  ['node toolchain', NODE_TOOLCHAIN],
  ['other toolchains', OTHER_TOOLCHAINS],
  ['git', GIT],
  ['containers and cloud', CONTAINERS_AND_CLOUD],
  ['routine cleanup', ROUTINE_CLEANUP],
  ['ordinary http', ORDINARY_HTTP],
  ['chains and redirection', CHAINS_AND_REDIRECTION],
  ['processes', PROCESSES],
];

for (const [groupName, commands] of GROUPS) {
  describe(`no false positive — ${groupName}`, () => {
    for (const command of commands) {
      it(`allows silently: ${command}`, async () => {
        const decision = await decideCommand(command);
        assert.equal(
          decision.verdict,
          'allow',
          `FALSE POSITIVE — ${JSON.stringify(command)} was ${decision.verdict}.\n` +
            `  reason: ${decision.reason}\n` +
            `  rules:  ${decision.findings.map((f) => f.rule).join(', ') || '(none)'}`,
        );
      });
    }
  });
}

describe('false positives — suite integrity', () => {
  it('covers a broad corpus with no duplicates', () => {
    const all = GROUPS.flatMap(([, commands]) => commands);
    assert.equal(new Set(all).size, all.length, 'duplicate command in the ordinary corpus');
    assert.ok(all.length >= 139, `ordinary corpus shrank to ${all.length} commands`);
  });
});
