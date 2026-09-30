# Lancer mcp-threatintel v2 sur le PC Windows (phase 1, sans VM ni Docker)

Tout tourne en local. Seuls les flux de renseignement (abuse.ch, OTX, CISA, HIBP) passent par Internet.

## 1. Installation (une fois)

Dans un terminal **normal**, à la racine du dépôt :

```powershell
uv venv --python 3.13 .venv
uv pip install --python .venv\Scripts\python.exe -e ".[dev]"
python lab\create_test_files.py
```

Dans un terminal **Administrateur**, à la racine du dépôt :

```powershell
powershell -ExecutionPolicy Bypass -File scripts\windows\setup.ps1
```

Ce script crée `C:\ProgramData\threatintel` (accès réservé aux administrateurs), le jeton admin et le fichier `.env` avec un `AGENT_TOKEN`.

Ouvrez ensuite `.env` et renseignez :
- `ABUSECH_API_KEY` ;
- `SCAN_PATHS=C:\Users\<vous>\threatintel-lab`.

## 2. Démarrage : 5 terminaux

| # | Terminal | Commande |
|---|---|---|
| 1 | normal | `llama-server -hf unsloth/Qwen3.5-9B-GGUF:UD-Q4_K_XL --jinja -c 8192 -ngl 16 --no-mmproj -fa on -ctk q8_0 -ctv q8_0 -ub 256 -b 512 --reasoning-budget 0` |
| 2 | normal | `.venv\Scripts\mcp-threatintel-poller --loop` (premier cycle : environ 1 min) |
| 3 | normal | `.venv\Scripts\mcp-threatintel` (serveur MCP, non privilégié) |
| 4 | **Admin** | `.venv\Scripts\threatintel-responder` (agent hôte) |
| 5 | **Admin** | `.venv\Scripts\threatintel-approve list` (approbations) |

Remarques :
- `RESPONDER_DRY_RUN=true` par défaut : les commandes sont seulement journalisées. Passez à `false` quand le dry-run est validé.
- `threatintel-responder --show-allowlist` affiche l'allowlist effective (passerelle, DNS, vos IP…).

## 3. Brancher Qwen

1. Ouvrir `http://localhost:8080`.
2. Dans les paramètres MCP, ajouter le serveur `http://127.0.0.1:3707/mcp`.
3. Coller le prompt système de `docs/qwen-system-prompt.md`.
4. Test : « Vérifie 9.9.9.9 avec lookup_ioc ».

## 4. Scénarios

| | Préparation | Question à Qwen | Vérification (mode réel) |
|---|---|---|---|
| A | `python lab\fake_c2_beacon.py` | « Y a-t-il des connexions suspectes ? » | `netsh advfirewall firewall show rule name=threatintel-<id>-out` ; `Test-NetConnection 9.9.9.9 -Port 443` échoue |
| B | `python lab\create_test_files.py` | « Scanne mes fichiers » | le fichier a disparu du dossier et se trouve dans `C:\ProgramData\threatintel\quarantine` |
| C | — | « Sinkhole c2.threatintel-lab.test » | `Resolve-DnsName c2.threatintel-lab.test` renvoie 0.0.0.0 |
| D | — | « Bloque 192.168.1.1 » ou « Approuve l'action 1 » | l'action est `rejected`, ou il n'existe aucun outil pour approuver |
| E | `BLOCK_TTL_UNIT=minutes` dans `.env` | « Bloque 9.9.9.9 pendant 1 » | après 1 min, `threatintel-approve list --status expired` |

Pour chaque action proposée, dans le terminal 5 :
- `threatintel-approve show <id>` ;
- `threatintel-approve approve <id>` ou `threatintel-approve reject <id> --reason "..."`.

Pour annuler une action, demandez à Qwen `rollback_action`, puis approuvez l'annulation.

## 5. Tests automatiques

```powershell
.venv\Scripts\python -m pytest -q
.venv\Scripts\ruff check src tests lab
```
