import type { CoreContext, Ecosystem } from './types';

export interface PublishedVersion {
  version: string;
  publishedAt?: string;
}

const DEPSDEV_SYSTEM: Partial<Record<Ecosystem, string>> = {
  npm: 'npm',
  Maven: 'maven',
  PyPI: 'pypi',
  Go: 'go',
  'crates.io': 'cargo',
  NuGet: 'nuget',
};

const inflight = new Map<string, Promise<PublishedVersion[] | undefined>>();

/**
 * All publicly published versions of a package (deps.dev, RubyGems, Packagist), cached for 6 hours.
 * Returns undefined when the list cannot be determined (unsupported ecosystem, network error).
 */
export function listPublishedVersions(ctx: CoreContext, eco: Ecosystem, name: string): Promise<PublishedVersion[] | undefined> {
  const key = `${eco}|${name}`;
  const cached = ctx.cache.get<PublishedVersion[] | null>('versions', key);
  if (cached !== undefined) return Promise.resolve(cached ?? undefined);
  let p = inflight.get(key);
  if (!p) {
    p = fetchList(ctx, eco, name)
      .then((list) => {
        ctx.cache.set('versions', key, list ?? null, 6 * 3600_000);
        return list;
      })
      .catch((e) => {
        ctx.log.warn(`Version list ${key}: ${(e as Error).message}`);
        return undefined;
      })
      .finally(() => inflight.delete(key));
    inflight.set(key, p);
  }
  return p;
}

async function fetchList(ctx: CoreContext, eco: Ecosystem, name: string): Promise<PublishedVersion[] | undefined> {
  const system = DEPSDEV_SYSTEM[eco];
  if (system) {
    const doc = await ctx.http.jsonOrUndefined<{ versions?: { versionKey: { version: string }; publishedAt?: string }[] }>(
      `https://api.deps.dev/v3/systems/${system}/packages/${encodeURIComponent(name)}`,
    );
    return doc?.versions?.map((v) => ({ version: v.versionKey.version, publishedAt: v.publishedAt }));
  }
  if (eco === 'RubyGems') {
    const doc = await ctx.http.jsonOrUndefined<{ number: string; created_at: string }[]>(`https://rubygems.org/api/v1/versions/${encodeURIComponent(name)}.json`);
    return doc?.map((v) => ({ version: v.number, publishedAt: v.created_at }));
  }
  if (eco === 'Packagist') {
    const doc = await ctx.http.jsonOrUndefined<{ packages?: Record<string, { version: string; time?: string }[]> }>(`https://repo.packagist.org/p2/${name}.json`);
    return doc?.packages?.[name]?.map((v) => ({ version: v.version.replace(/^v/, ''), publishedAt: v.time }));
  }
  return undefined;
}

/** Normalised set for membership checks ("v1.2.3" and "1.2.3" are the same). */
export function versionSet(list: PublishedVersion[] | undefined): Set<string> | undefined {
  if (!list?.length) return undefined;
  const s = new Set<string>();
  for (const v of list) s.add(v.version.replace(/^v(?=\d)/, ''));
  return s;
}
