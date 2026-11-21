/** Frequently-targeted popular package names used for typosquat detection. */
export const POPULAR: Partial<Record<string, string[]>> = {
  npm: [
    'react', 'react-dom', 'lodash', 'express', 'axios', 'chalk', 'commander', 'debug', 'moment', 'request', 'webpack', 'typescript',
    'vue', 'angular', 'jquery', 'underscore', 'async', 'bluebird', 'uuid', 'dotenv', 'yargs', 'minimist', 'glob', 'rimraf', 'mkdirp',
    'semver', 'colors', 'body-parser', 'cross-env', 'eslint', 'prettier', 'babel-core', 'jest', 'mocha', 'chai', 'next', 'nuxt',
    'socket.io', 'mongoose', 'mongodb', 'mysql', 'mysql2', 'redis', 'pg', 'sequelize', 'knex', 'jsonwebtoken', 'bcrypt', 'bcryptjs',
    'passport', 'cors', 'helmet', 'morgan', 'nodemon', 'node-fetch', 'cheerio', 'puppeteer', 'electron', 'inquirer', 'ora', 'ws',
    'classnames', 'prop-types', 'redux', 'react-redux', 'react-router', 'react-router-dom', 'styled-components', 'tailwindcss',
    'postcss', 'autoprefixer', 'sass', 'less', 'vite', 'rollup', 'esbuild', 'zod', 'yup', 'formik', 'dayjs', 'date-fns', 'rxjs',
    'graphql', 'apollo-server', 'fs-extra', 'shelljs', 'execa', 'got', 'superagent', 'qs', 'ms', 'nanoid', 'supports-color',
    'ansi-styles', 'strip-ansi', 'ansi-regex', 'wrap-ansi', 'color-convert', 'color-name', 'is-arrayish', 'error-ex',
    'simple-swizzle', 'has-ansi', 'slice-ansi', 'chalk-template', 'backslash', 'event-stream', 'ua-parser-js', 'coa', 'rc',
    'node-ipc', 'eslint-scope', 'electron-native-notify', 'discord.js', 'ethers', 'web3', 'crypto-js', 'tslib', 'core-js',
    'zone.js', 'kleur', 'picocolors', 'immer', 'lru-cache', 'tar', 'node-sass', 'nx', 'tinycolor2', 'is', 'duckdb',
  ],
  PyPI: [
    'requests', 'urllib3', 'numpy', 'pandas', 'django', 'flask', 'boto3', 'botocore', 'setuptools', 'six', 'python-dateutil',
    'pyyaml', 'certifi', 'idna', 'charset-normalizer', 'cryptography', 'pip', 'wheel', 'jinja2', 'markupsafe', 'click',
    'attrs', 'pytest', 'scipy', 'matplotlib', 'pillow', 'sqlalchemy', 'psycopg2', 'pymongo', 'redis', 'celery', 'beautifulsoup4',
    'lxml', 'selenium', 'scrapy', 'tensorflow', 'torch', 'keras', 'scikit-learn', 'opencv-python', 'fastapi', 'uvicorn',
    'pydantic', 'aiohttp', 'httpx', 'paramiko', 'colorama', 'tqdm', 'openai', 'anthropic', 'transformers', 'langchain',
    'jwt', 'pyjwt', 'python-dotenv', 'docker', 'kubernetes', 'ansible', 'gunicorn', 'werkzeug', 'pycryptodome', 'pysocks',
    'discord', 'web3', 'ctx', 'termcolor', 'rich', 'typer', 'httplib2', 'protobuf', 'grpcio', 'pyopenssl', 'tornado',
  ],
  RubyGems: ['rails', 'rack', 'nokogiri', 'devise', 'puma', 'sidekiq', 'rspec', 'bundler', 'rake', 'json', 'activesupport', 'faraday', 'httparty', 'rest-client', 'bootstrap-sass', 'strong_password', 'rubocop'],
  'crates.io': ['serde', 'tokio', 'rand', 'clap', 'reqwest', 'hyper', 'regex', 'log', 'syn', 'quote', 'anyhow', 'thiserror', 'chrono', 'futures', 'serde_json', 'time', 'libc', 'lazy_static', 'rustdecimal', 'rust_decimal'],
  Packagist: ['laravel/framework', 'symfony/symfony', 'guzzlehttp/guzzle', 'monolog/monolog', 'phpunit/phpunit', 'doctrine/orm'],
  NuGet: ['Newtonsoft.Json', 'Serilog', 'AutoMapper', 'Dapper', 'Polly', 'MediatR', 'FluentValidation', 'Moq', 'xunit', 'NUnit'],
};

/** Damerau–Levenshtein (optimal string alignment) distance, capped. */
export function editDistance(a: string, b: string, max = 3): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i, ...new Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}

/** Name without separators: 'cross-env' -> 'crossenv'. */
const unsep = (s: string) => s.toLowerCase().replace(/[-_.]/g, '');

/** Returns the popular package a name appears to imitate, if any. */
export function typosquatTarget(ecosystem: string, name: string): string | undefined {
  const list = POPULAR[ecosystem];
  if (!list) return undefined;
  const lower = name.toLowerCase();
  if (list.some((p) => p.toLowerCase() === lower)) return undefined;
  // Scoped npm packages (@scope/name) are owned per scope and verified by the registry, so the bare name
  // ("@secretlint/core") says nothing about imitating an unscoped popular package ("core-js").
  if (ecosystem === 'npm' && lower.startsWith('@')) return undefined;
  const bare = lower;
  for (const p of list) {
    const pl = p.toLowerCase();
    if (pl.length < 4) continue;
    if (bare === pl && lower !== pl && ecosystem === 'npm') continue; // @scope/react is fine-ish (scoped forks are common)
    // Same name with different separators (crossenv vs cross-env) …
    if (unsep(bare) === unsep(pl) && bare !== pl) return p;
    // … or a "js" suffix added to a popular name (lodashjs, lodash-js). Dropping a popular package's own
    // suffix (core vs core-js) is not imitation.
    if (!unsep(pl).endsWith('js') && unsep(bare) === unsep(pl) + 'js') return p;
    if (pl.length >= 5 && bare.length >= 5 && editDistance(bare, pl, 1) === 1) return p;
    // Bait suffixes commonly used by impostors.
    if (new RegExp(`^${escapeRe(pl)}[-_.]?(official|secure|latest|fixed|patched)$`).test(bare)) return p;
  }
  return undefined;
}

/** Legitimate packages that are one edit away from a popular one. */
const KNOWN_LEGIT = new Set(['preact', 'color', 'colors', 'ether', 'axios-retry', 'chai', 'mocha', 'react-is', 'requests', 'request', 'uuidv4', 'semver', 'rimraf', 'execa', 'globby', 'redux', 'redis', 'nanoid', 'got', 'jsonwebtoken', 'tqdm', 'scipy', 'numpy', 'attr', 'attrs', 'click', 'six', 'idna', 'time', 'rand', 'log', 'syn', 'serde', 'tokio']);

export function isTyposquat(ecosystem: string, name: string): string | undefined {
  if (KNOWN_LEGIT.has(name.toLowerCase())) return undefined;
  return typosquatTarget(ecosystem, name);
}

function escapeRe(s: string) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
