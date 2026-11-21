/** OSV ecosystem identifiers (https://ossf.github.io/osv-schema/#affectedpackage-field). */
export type Ecosystem = 'npm' | 'Maven' | 'PyPI' | 'Go' | 'crates.io' | 'RubyGems' | 'Packagist' | 'NuGet';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  unknown: 2,
  low: 1,
};

export type PkgSource = 'registry' | 'git' | 'file' | 'url' | 'workspace' | 'unknown';

export interface PkgNode {
  /** Unique key inside a graph: `name@version`. */
  key: string;
  name: string;
  version: string;
  /** Keys of dependencies of this package. */
  deps: string[];
  dev?: boolean;
  optional?: boolean;
  /** Tarball / download URL recorded in the lockfile. */
  resolved?: string;
  integrity?: string;
  hasInstallScript?: boolean;
  source?: PkgSource;
}

export interface DependencyGraph {
  ecosystem: Ecosystem;
  /** The file that was parsed (lockfile or manifest). */
  file: string;
  /** Companion manifest (e.g. package.json next to package-lock.json) used to locate direct deps. */
  manifestFile?: string;
  nodes: Map<string, PkgNode>;
  /** Keys of direct dependencies. */
  roots: string[];
  warnings: string[];
}

export interface Vulnerability {
  id: string;
  aliases: string[];
  summary: string;
  details?: string;
  severity: Severity;
  cvssScore?: number;
  fixedVersions: string[];
  references: string[];
  url: string;
  published?: string;
  modified?: string;
  isMalicious: boolean;
  /** Listed in CISA's Known Exploited Vulnerabilities catalog: exploitation in the wild is confirmed. */
  kev?: { dateAdded: string; ransomware: boolean };
  /** FIRST EPSS: probability (0-1) of exploitation in the next 30 days, and its percentile among all CVEs. */
  epss?: { score: number; percentile: number };
}

export interface SupplyChainSignal {
  code: string;
  severity: Severity;
  message: string;
  score: number;
}

export interface PackageFinding {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  key: string;
  direct: boolean;
  dev: boolean;
  /** Shortest dependency chain from a direct dependency to this package (names@versions, root first, excluding the package itself). */
  via: string[];
  /** Direct dependency that pulls the package in (for transitive deps). */
  introducedBy?: string;
  vulns: Vulnerability[];
  signals: SupplyChainSignal[];
  riskScore: number;
  suspicious: boolean;
  /** Highest severity across vulns and signals. */
  maxSeverity: Severity;
  /** Lowest version that fixes every fixable advisory. */
  fixVersion?: string;
  /** Advisory ids without any fixed version above the current one. */
  unfixed?: string[];
  /** Best upgrade on the current major line and how many advisories it fixes. */
  safeFixVersion?: string;
  safeFixCount?: number;
}

export interface FileResult {
  file: string;
  manifestFile?: string;
  ecosystem: Ecosystem;
  packageCount: number;
  findings: PackageFinding[];
  warnings: string[];
  error?: string;
  scannedAt: string;
}

export interface ScanResult {
  startedAt: string;
  finishedAt: string;
  files: FileResult[];
}

export interface CoreConfig {
  includeDev: boolean;
  resolveTransitive: boolean;
  maxDepth: number;
  mavenRepos: string[];
  npmRegistry: string;
  ignoredAdvisories: string[];
  minimumSeverity: Severity;
  /** Look up real-world exploitation data (CISA KEV, FIRST EPSS) for CVEs. Default: on. */
  exploitData?: boolean;
  supplyChain: {
    enabled: boolean;
    recentPublishHours: number;
    threshold: number;
    allowedRegistries: string[];
    trustedPackages: string[];
    maxRegistryLookups: number;
  };
}

export interface Logger {
  info(msg: string): void;
  warn(msg: string): void;
  error(msg: string): void;
}

export interface Cache {
  get<T>(ns: string, key: string): T | undefined;
  set<T>(ns: string, key: string, value: T, ttlMs?: number): void;
  clear(): Promise<void>;
  flush(): Promise<void>;
}

export interface CoreContext {
  config: CoreConfig;
  cache: Cache;
  log: Logger;
  http: import('./http').Http;
  readFile(path: string): Promise<string | undefined>;
  /** Directories the scanner may read from (workspace folders / CLI root). Paths outside are never read. */
  allowedRoots?: string[];
  /** Cancellation check. */
  isCancelled?(): boolean;
}

export function pkgKey(name: string, version: string): string {
  return `${name}@${version}`;
}
