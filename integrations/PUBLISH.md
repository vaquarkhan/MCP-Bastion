# Publishing Bastion integration packages to PyPI

Each `integrations/mcp-bastion-*` folder is its **own PyPI project**. Core stays **`mcp-bastion-python`**.

| Item | Value |
|------|-------|
| **GitHub repo** | `vaquarkhan/MCP-Bastion` |
| **Repo URL** | https://github.com/vaquarkhan/MCP-Bastion |
| **Workflow file** | `.github/workflows/publish-integrations.yml` |
| **Workflow name (Actions UI)** | **Publish Integration Packages** |
| **Core dependency** | `mcp-bastion-python>=4.0.0,<5` (publish core first) |
| **Integration version** | `4.0.0` in each package `pyproject.toml` |

## New packages (published @ 4.0.0)

All eight are on PyPI. Download totals: [Integrations dashboard](https://vaquarkhan.github.io/MCP-Bastion/integrations.html) · [ecosystem-downloads.json](../docs/site/assets/ecosystem-downloads.json).

| # | PyPI project name | Folder | Import | Status |
|---|-------------------|--------|--------|--------|
| 1 | `mcp-bastion-litellm` | `integrations/mcp-bastion-litellm` | `mcp_bastion_litellm` | **Published** |
| 2 | `mcp-bastion-langgraph` | `integrations/mcp-bastion-langgraph` | `mcp_bastion_langgraph` | **Published** |
| 3 | `mcp-bastion-pydantic-ai` | `integrations/mcp-bastion-pydantic-ai` | `mcp_bastion_pydantic_ai` | **Published** |
| 4 | `mcp-bastion-openai-agents` | `integrations/mcp-bastion-openai-agents` | `mcp_bastion_openai_agents` | **Published** |
| 5 | `mcp-bastion-ollama` | `integrations/mcp-bastion-ollama` | `mcp_bastion_ollama` | **Published** |
| 6 | `mcp-bastion-openrouter` | `integrations/mcp-bastion-openrouter` | `mcp_bastion_openrouter` | **Published** |
| 7 | `mcp-bastion-xai` | `integrations/mcp-bastion-xai` | `mcp_bastion_xai` | **Published** |
| 8 | `mcp-bastion-autogen` | `integrations/mcp-bastion-autogen` | `mcp_bastion_autogen` | **Published** |

Total product line: **26** packages (1 core + 25 integrations).

---

## Option A — GitHub Actions (recommended)

### 1. Merge code to `main`

Commit/push all `integrations/mcp-bastion-*` folders + updated `publish-integrations.yml` + README.

### 2. Trusted Publisher on PyPI (once per **new** package)

For **each** new name (`mcp-bastion-litellm`, …):

1. Go to https://pypi.org/manage/account/publishing/  
   (or after first upload: Project → **Settings** → **Publishing**)
2. **Add a new pending publisher** with:

| Field | Value |
|-------|-------|
| PyPI Project Name | `mcp-bastion-litellm` (change per package) |
| Owner | `vaquarkhan` |
| Repository name | `MCP-Bastion` |
| Workflow name | `publish-integrations.yml` |
| Environment name | *(leave blank)* |

Repeat for all 8 names above.

> First-time tip: if PyPI requires the project to exist first, do **one** manual `twine upload` (Option B), then attach Trusted Publishing for later releases.

### 3. Run the workflow

1. https://github.com/vaquarkhan/MCP-Bastion/actions/workflows/publish-integrations.yml  
2. **Run workflow**
3. Branch: `main`
4. Package: pick **one** (e.g. `mcp-bastion-litellm`) — do **not** use `all` on first day if Trusted Publisher is only set for some packages
5. Confirm job green → package appears on PyPI

Optional tag trigger: push a tag matching `integration-v*` (e.g. `integration-v4.0.0`).

### 4. Verify

```text
https://pypi.org/project/mcp-bastion-litellm/
```

```bash
pip install mcp-bastion-litellm==4.0.0
python -c "from mcp_bastion_litellm import SecureLiteLLM; print(SecureLiteLLM)"
```

---

## Option B — Manual twine (one package at a time)

```powershell
python -m pip install -U build twine hatchling

$PKG = "mcp-bastion-litellm"   # change each time
cd C:\Users\Administrator\Downloads\mcp\MCP-Bastion\integrations\$PKG
Remove-Item -Recurse -Force dist, build -ErrorAction SilentlyContinue
python -m build
$env:TWINE_USERNAME = "__token__"
$env:TWINE_PASSWORD = "pypi-YOUR_TOKEN_HERE"
python -m twine upload dist/*
```

Then next:

```powershell
$PKG = "mcp-bastion-langgraph"
# … same build + twine steps
```

Full list for copy-paste:

```text
mcp-bastion-litellm
mcp-bastion-langgraph
mcp-bastion-pydantic-ai
mcp-bastion-openai-agents
mcp-bastion-ollama
mcp-bastion-openrouter
mcp-bastion-xai
mcp-bastion-autogen
```

---

## Checklist per package

- [ ] Folder exists under `integrations/<name>/`
- [ ] `pyproject.toml` → `name` matches PyPI name, `version = "4.0.0"`
- [ ] `mcp-bastion-python` 4.x already on PyPI
- [ ] Trusted Publisher **or** API token ready
- [ ] Build + upload succeeded
- [ ] `pip install <name>==4.0.0` works
- [ ] README badge row already present (fills in after first publish)

## Nature reminder

These adapters only wrap Bastion pillars in-process. They do **not** add a gateway, SaaS, or OAuth server.
