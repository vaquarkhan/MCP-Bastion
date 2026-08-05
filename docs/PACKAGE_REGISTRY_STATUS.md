# Package registry status (org-friendly installs)

**Last checked:** 2026-07-31  
**Goal:** Every language can install from a **public registry** without downloading GitHub Release assets locally (many orgs block that).

## Status matrix

| Package | Registry | Version | Public download? | Notes |
|---------|----------|---------|------------------|-------|
| `mcp-bastion-python` | **PyPI** | 4.0.0 | **YES** | `pip install mcp-bastion-python==4.0.0` |
| 25× `mcp-bastion-*` integrations | **PyPI** | 4.0.0 | **YES** | e.g. `mcp-bastion-openai`, `mcp-bastion-litellm`, `mcp-bastion-fastmcp`, … |
| `ghcr.io/vaquarkhan/mcp-bastion-proxy` | **GHCR** | v4.0.0 | **YES** | Public container |
| `ghcr.io/vaquarkhan/mcp-bastion-dashboard` | **GHCR** | v4.0.0 | **YES** | Public container |
| `ghcr.io/vaquarkhan/mcp-bastion-suite` | **GHCR** | 0.1.0 | **YES** | Public container |
| Go `…/adapters/go` | **proxy.golang.org** | v0.1.0 | **YES** | `go get …@v0.1.0` |
| `@mcp-bastion/core` | npmjs.org | — | **NO** | Never bootstrapped; needs `NPM_TOKEN` once |
| `@vaquarkhan/mcp-bastion-suite` | npmjs.org | — | **NO** | Only GitHub Packages (401 without PAT) |
| `io.github.vaquarkhan:mcp-bastion-suite` | **Maven Central** | — | **NO** | `numFound=0`; JAR only on GH Release / private GH Packages |
| `McpBastionSuite` | **NuGet.org** | — | **NO** | Only GitHub Packages / Release `.nupkg` |
| GitHub Packages (Maven/npm/NuGet) | maven/npm.pkg.github.com | 0.1.0 | **NO (401)** | Not usable without `read:packages` PAT |

## What works today in locked-down orgs

```bash
# Engine + integrations (recommended for everyone)
pip install "mcp-bastion-python==4.0.0"
pip install "mcp-bastion-openai==4.0.0"

# Boundary / CLI without language adapters
docker pull ghcr.io/vaquarkhan/mcp-bastion-proxy:v4.0.0
docker pull ghcr.io/vaquarkhan/mcp-bastion-suite:0.1.0

# Go adapter (public module proxy)
go get github.com/vaquarkhan/mcp-bastion-suite/adapters/go@v0.1.0
```

Java / TypeScript / .NET **cannot** currently resolve from Maven Central / npmjs / NuGet.org. Point those stacks at the **Docker proxy** + shared `bastion.yaml` until public packages exist:

```bash
docker run --rm -p 8080:8080 -v "$PWD/bastion.yaml:/config/bastion.yaml" \
  ghcr.io/vaquarkhan/mcp-bastion-suite:0.1.0 serve --proxy --config /config/bastion.yaml
```

## Gaps to publish (action required)

### 1. npm `@mcp-bastion/core` (MCP-Bastion repo)

1. Create granular npm token (read/write).  
2. Repo secret `NPM_TOKEN` on `vaquarkhan/MCP-Bastion`.  
3. Actions → **Build, Test, and Publish MCP-Bastion** → publish=true (or push `v*` tag).  
4. Configure Trusted Publisher on npmjs.com (see [PUBLISHING_NPM_AND_REGISTRY.md](PUBLISHING_NPM_AND_REGISTRY.md)).

### 2. Java → Maven Central (`io.github.vaquarkhan:mcp-bastion-suite`)

GitHub Packages is **not** enough for orgs that block PAT / local JAR install. Need:

1. Sonatype Central Portal account for `io.github.vaquarkhan` (same group already used for other artifacts).  
2. Secrets on `mcp-bastion-suite`: e.g. `CENTRAL_USERNAME` / `CENTRAL_TOKEN` (or OSSRH pair).  
3. Extend **Publish language adapters** workflow to deploy with `central-publishing-maven-plugin` (or `mvn deploy` to Central).  
4. Cut a new version (e.g. `0.1.1`) so Central gets a clean publish.

### 3. TypeScript suite → npmjs.org (`@vaquarkhan/mcp-bastion-suite` or `@mcp-bastion/suite`)

1. Prefer scope `@mcp-bastion` on npmjs (public) **or** publish `@vaquarkhan/…` with npm access.  
2. Secret `NPM_TOKEN` on `mcp-bastion-suite`.  
3. Change adapter publish job `registry-url` from `npm.pkg.github.com` → `https://registry.npmjs.org`.

### 4. .NET → NuGet.org (`McpBastionSuite`)

1. Create nuget.org API key.  
2. Secret `NUGET_API_KEY` on `mcp-bastion-suite`.  
3. Push with `dotnet nuget push --source https://api.nuget.org/v3/index.json`.

### 5. Optional interim: public GitHub Packages

If Central/npmjs/nuget.org take time, set each GH Package visibility to **Public** (UI or `PACKAGES_TOKEN` with `write:packages`). Still often blocked in enterprises that only allow Maven Central / npmjs / nuget.org.

## Verify script

```bash
python scripts/verify_package_registries.py
```

Exits non-zero if any expected public package is missing.

## Related

- Suite publishing: https://github.com/vaquarkhan/mcp-bastion-suite/blob/main/docs/PUBLISHING.md  
- npm bootstrap: [PUBLISHING_NPM_AND_REGISTRY.md](PUBLISHING_NPM_AND_REGISTRY.md)  
- Multi-language install: [MULTI_LANGUAGE_SUITE.md](MULTI_LANGUAGE_SUITE.md)  
