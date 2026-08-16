# Multi-language suite ([mcp-bastion-suite](https://github.com/vaquarkhan/mcp-bastion-suite))

**MCP-Bastion** (this repo) is the **security engine** published as [`mcp-bastion-python`](https://pypi.org/project/mcp-bastion-python/) on PyPI—middleware, pillars, dashboard, CLI (`validate`, `scan`, `serve --proxy`, …).

**[mcp-bastion-suite](https://github.com/vaquarkhan/mcp-bastion-suite)** is the **multi-language connector layer**: shared `bastion.yaml`, language adapters, tutorials, Docker, and a GitHub Action. It does **not** vendor Bastion source; the engine always comes from PyPI.

> **Prerequisite (D-3):** Java / Go / .NET / suite adapters invoke the **`mcp-bastion` Python CLI** at **runtime**. Install the engine first and confirm `mcp-bastion doctor` reports `cli_on_path` OK — a missing Python/`mcp-bastion` on `PATH` fails at run time, not build time.

> **Honest scope today:** full in-process pillars are **Python**. Scan / red-team / `serve --proxy` work for any language over MCP HTTP. Suite Java / Go / .NET adapters are **CLI wrappers** around the Python engine (require `mcp-bastion` / Python on `PATH` — run `mcp-bastion doctor` early). `@mcp-bastion/core` (Node) has native rate limiting, optional result provenance tags, and a hash-chained audit; ML pillars (prompt guard, PII, semantic egress, result guard) need a Python sidecar URL (`sidecarUrl` / `MCP_BASTION_URL`) and **fail closed** in quarantine/strict modes if the sidecar is missing. The suite TypeScript package is a config helper only — use `@mcp-bastion/core` for runtime. See [MULTI-LANGUAGE-STRATEGY.md](MULTI-LANGUAGE-STRATEGY.md) and [CYBER_EXTENSIONS_CORE.md](CYBER_EXTENSIONS_CORE.md).

> Keep deep language tutorials and framework packs in the suite repo so this README stays light. This page is the bridge.

---

## How the two repos relate

```text
┌─────────────────────────────────────────────────────────┐
│  Your app (Nest, Spring, FastAPI, .NET, Go, Rust, …)    │
└───────────────────────────┬─────────────────────────────┘
                            │
        ┌───────────────────▼───────────────────┐
        │  mcp-bastion-suite                       │
        │  adapters · YAML/CLI · sidecar · proxy   │
        │  https://github.com/vaquarkhan/mcp-bastion-suite
        └───────────────────┬───────────────────┘
                            │  bastion.yaml (shared policy)
                            ▼
        ┌───────────────────────────────────────┐
        │  mcp-bastion-python  (this project)     │
        │  Scan → Test → Enforce · dashboard      │
        │  pip install mcp-bastion-python         │
        └───────────────────────────────────────┘
```

| Repo | Role |
|------|------|
| [MCP-Bastion](https://github.com/vaquarkhan/MCP-Bastion) | Engine + Python middleware + docs site + attack demos |
| [mcp-bastion-suite](https://github.com/vaquarkhan/mcp-bastion-suite) | Connectors for every language / framework |

Engine contract in the suite: [docs/PYPI_ENGINE.md](https://github.com/vaquarkhan/mcp-bastion-suite/blob/main/docs/PYPI_ENGINE.md).

**Org-friendly registry audit:** [PACKAGE_REGISTRY_STATUS.md](PACKAGE_REGISTRY_STATUS.md) — what is on PyPI / npmjs / Maven Central / NuGet.org / GHCR (and what is still missing).

---

## Install matrix (suite)

| You use | Install |
|---------|---------|
| **Python engine** | `pip install mcp-bastion-python` |
| **Suite CLI** | `pip install "git+https://github.com/vaquarkhan/mcp-bastion-suite.git"` then `mcp-bastion-suite doctor` |
| **Node / TypeScript** | npm GitHub Packages `@vaquarkhan/mcp-bastion-suite` **or** download `.tgz` from [Release v0.1.0](https://github.com/vaquarkhan/mcp-bastion-suite/releases/tag/v0.1.0) |
| **Java / Kotlin** | **Not on Maven Central** — see [Java JAR below](#java--kotlin-maven-jar) |
| **Go** | `go get github.com/vaquarkhan/mcp-bastion-suite/adapters/go@v0.1.0` |
| **.NET** | NuGet GitHub Packages `McpBastionSuite` **or** `.nupkg` from [Release v0.1.0](https://github.com/vaquarkhan/mcp-bastion-suite/releases/tag/v0.1.0) |
| **Any / CI** | `ghcr.io/vaquarkhan/mcp-bastion-suite` or [GitHub Action](https://github.com/vaquarkhan/mcp-bastion-suite/blob/main/action.yml) |

Full commands: [suite DOWNLOADS.md](https://github.com/vaquarkhan/mcp-bastion-suite/blob/main/docs/DOWNLOADS.md) · Release assets: [v0.1.0](https://github.com/vaquarkhan/mcp-bastion-suite/releases/tag/v0.1.0)

### Java / Kotlin (Maven JAR)

The adapter JAR is published as a **GitHub Release asset**, not Maven Central. That is why search.maven.org / Maven Central UI will not show it.

**Option A — download JAR (no registry auth)**

```text
https://github.com/vaquarkhan/mcp-bastion-suite/releases/download/v0.1.0/mcp-bastion-suite-0.1.0.jar
https://github.com/vaquarkhan/mcp-bastion-suite/releases/download/v0.1.0/pom.xml
```

Install into your local Maven repo:

```bash
mvn install:install-file \
  -Dfile=mcp-bastion-suite-0.1.0.jar \
  -DpomFile=pom.xml \
  -DgroupId=io.github.vaquarkhan \
  -DartifactId=mcp-bastion-suite \
  -Dversion=0.1.0 \
  -Dpackaging=jar
```

Then in `pom.xml`:

```xml
<dependency>
  <groupId>io.github.vaquarkhan</groupId>
  <artifactId>mcp-bastion-suite</artifactId>
  <version>0.1.0</version>
</dependency>
```

**Option B — GitHub Packages** (needs a PAT with `read:packages`; package visibility may be private until set Public in GitHub → Packages)

```xml
<repositories>
  <repository>
    <id>github</id>
    <url>https://maven.pkg.github.com/vaquarkhan/mcp-bastion-suite</url>
  </repository>
</repositories>
```

`~/.m2/settings.xml`:

```xml
<server>
  <id>github</id>
  <username>YOUR_GITHUB_USERNAME</username>
  <password>YOUR_PAT_WITH_read:packages</password>
</server>
```

**Important:** The Java adapter is a thin connector. The security engine is still **`mcp-bastion-python`** (CLI / sidecar / proxy). Install the engine:

```bash
pip install "mcp-bastion-python>=5.1.0,<6"
# or use suite Docker: ghcr.io/vaquarkhan/mcp-bastion-suite:0.1.0
```

Tutorial: [suite java.md](https://github.com/vaquarkhan/mcp-bastion-suite/blob/main/docs/tutorials/java.md)

Shared policy sketch (same file in every language):

```yaml
prompt_guard:
  enabled: true
  threshold: 0.85
  heuristic_fallback: true
pii:
  enabled: true
rate_limit:
  enabled: true
  max_iterations: 15
  timeout_seconds: 60
mode: enforce
```

```bash
cp bastion.yaml.example bastion.yaml   # from the suite clone
mcp-bastion-suite validate --config bastion.yaml
mcp-bastion-suite scan examples/_shared/data/tools.json --format json -o .bastion/scan/catalog.json
```

---

## How each language works

All languages share **one policy** and one engine. Adapters differ only in *how* traffic reaches Bastion (in-process Python vs sidecar/proxy).

| Language | How it works | Suite tutorial | Runnable example |
|----------|--------------|----------------|------------------|
| **Any (YAML)** | CLI validate/scan/doctor; enforce via proxy | [yaml.md](https://github.com/vaquarkhan/mcp-bastion-suite/blob/main/docs/tutorials/yaml.md) | [examples/declarative](https://github.com/vaquarkhan/mcp-bastion-suite/tree/main/examples/declarative) |
| **Python / FastMCP** | In-process `mcp-bastion-python` middleware | [python.md](https://github.com/vaquarkhan/mcp-bastion-suite/blob/main/docs/tutorials/python.md) · [fastmcp.md](https://github.com/vaquarkhan/mcp-bastion-suite/blob/main/docs/tutorials/fastmcp.md) | [frameworks/python](https://github.com/vaquarkhan/mcp-bastion-suite/tree/main/examples/frameworks/python) |
| **TypeScript** (Nest / Express / Fastify) | Adapter + sidecar / shared yaml | [typescript.md](https://github.com/vaquarkhan/mcp-bastion-suite/blob/main/docs/tutorials/typescript.md) | [frameworks/typescript](https://github.com/vaquarkhan/mcp-bastion-suite/tree/main/examples/frameworks/typescript) |
| **Java** (Spring Boot / Spring AI / Quarkus / Micronaut) | Java adapter + proxy to PyPI engine | [java.md](https://github.com/vaquarkhan/mcp-bastion-suite/blob/main/docs/tutorials/java.md) · [spring-boot.md](https://github.com/vaquarkhan/mcp-bastion-suite/blob/main/docs/tutorials/spring-boot.md) | [frameworks/java](https://github.com/vaquarkhan/mcp-bastion-suite/tree/main/examples/frameworks/java) · [spring-boot](https://github.com/vaquarkhan/mcp-bastion-suite/tree/main/examples/frameworks/spring-boot) |
| **Kotlin** | Same Maven artifact; Ktor / Spring | [kotlin.md](https://github.com/vaquarkhan/mcp-bastion-suite/blob/main/docs/tutorials/kotlin.md) | [frameworks/kotlin](https://github.com/vaquarkhan/mcp-bastion-suite/tree/main/examples/frameworks/kotlin) |
| **Go** | Go adapter + proxy | [go.md](https://github.com/vaquarkhan/mcp-bastion-suite/blob/main/docs/tutorials/go.md) | [frameworks/go](https://github.com/vaquarkhan/mcp-bastion-suite/tree/main/examples/frameworks/go) |
| **.NET** | NuGet adapter + proxy | [dotnet.md](https://github.com/vaquarkhan/mcp-bastion-suite/blob/main/docs/tutorials/dotnet.md) | [frameworks/dotnet](https://github.com/vaquarkhan/mcp-bastion-suite/tree/main/examples/frameworks/dotnet) |
| **Rust** | YAML + CLI + proxy (no native engine fork) | [rust.md](https://github.com/vaquarkhan/mcp-bastion-suite/blob/main/docs/tutorials/rust.md) | [frameworks/rust](https://github.com/vaquarkhan/mcp-bastion-suite/tree/main/examples/frameworks/rust) |
| **Third-party MCP** | HTTP boundary only | [proxy.md](https://github.com/vaquarkhan/mcp-bastion-suite/blob/main/docs/tutorials/proxy.md) | — |

Architecture deep dive: [suite MULTI_LANGUAGE.md](https://github.com/vaquarkhan/mcp-bastion-suite/blob/main/docs/MULTI_LANGUAGE.md).  
Tutorial index: [suite docs/tutorials](https://github.com/vaquarkhan/mcp-bastion-suite/tree/main/docs/tutorials).

### Typical non-Python path

1. Author `bastion.yaml` (same as Python).  
2. `mcp-bastion-suite validate` / `scan` in CI (Action or Docker).  
3. Run engine as **proxy/sidecar** (`mcp-bastion serve --proxy` or suite helper).  
4. Point Nest/Spring/.NET/Go MCP HTTP traffic at the proxy—or use the language adapter that stamps edge auth and forwards.

Python teams can stay in-process (this repo’s FastMCP wrap) without the suite; the suite still helps if you want one CI story across languages.

---

## Sample data & IDE

- CRM/support desk fixtures: [suite examples/_shared/data](https://github.com/vaquarkhan/mcp-bastion-suite/tree/main/examples/_shared/data)  
- Cursor / VS Code / Copilot: [suite IDE_INTEGRATION.md](https://github.com/vaquarkhan/mcp-bastion-suite/blob/main/docs/IDE_INTEGRATION.md)

---

## Feature parity

Validate, scan, red-team, dashboard, and **runtime enforce** are implemented by **mcp-bastion-python**. The suite unlocks that stack for other languages via adapters + shared policy.

- What each pillar does: [FEATURE_DEEP_DIVE.md](FEATURE_DEEP_DIVE.md)  
- Attack → defense scripts (Python engine): [ATTACK_DEMOS.md](ATTACK_DEMOS.md)  
- Enablement YAML: [FEATURES.md](FEATURES.md)

Upgrade engine only:

```bash
pip install -U "mcp-bastion-python>=5.1.0"
mcp-bastion-suite --version   # if suite CLI installed
```

---

## Docker / GitHub Action (suite)

```bash
docker pull ghcr.io/vaquarkhan/mcp-bastion-suite:0.1.0
docker run --rm -v "$PWD":/work -w /work ghcr.io/vaquarkhan/mcp-bastion-suite:0.1.0 \
  validate --config bastion.yaml
```

```yaml
- uses: vaquarkhan/mcp-bastion-suite@main
  with:
    command: validate
    config: bastion.yaml
```

---

## Where to go next

| Goal | Start here |
|------|------------|
| Understand Bastion pillars | [USER_GUIDE.md](USER_GUIDE.md) · [FEATURE_DEEP_DIVE.md](FEATURE_DEEP_DIVE.md) |
| Run attack demos (Python) | [ATTACK_DEMOS.md](ATTACK_DEMOS.md) |
| Adopt from Java/TS/Go/.NET | [mcp-bastion-suite](https://github.com/vaquarkhan/mcp-bastion-suite) → language tutorial |
| Proxy boundary | [GATEWAY_BOUNDARY.md](GATEWAY_BOUNDARY.md) · suite [proxy.md](https://github.com/vaquarkhan/mcp-bastion-suite/blob/main/docs/tutorials/proxy.md) |
