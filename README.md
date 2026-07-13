![](html/png/lldpq-banner.png)

```
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║     ██╗      ██╗      ██████╗   ██████╗    ██████╗       ║
║     ██║      ██║      ██╔══██╗  ██╔══██╗  ██╔═══██╗      ║
║     ██║      ██║      ██║  ██║  ██████╔╝  ██║   ██║      ║
║     ██║      ██║      ██║  ██║  ██╔═══╝   ██║▄▄ ██║      ║
║     ██████╗  ██████╗  ██████╔╝  ██║        ╚██████╔╝     ║
║     ╚═════╝  ╚═════╝  ╚═════╝   ╚═╝         ╚══▀▀═╝      ║
║                                                          ║
║      Network Monitoring for Cumulus Linux Switches       ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
```

simple network monitoring tool for Cumulus Linux switches

> *LLDPq is an independent project. It does not contain, derive from, or incorporate any code from any NVIDIA product.*
>
> *This software is provided "as is" without warranty. Always test in a lab environment before deploying to production networks.*

## Docker

For Docker installation, persistent volumes, DHCP/ONIE provisioning, updates,
streaming telemetry, rollback boundaries, and removal, see the
[Docker deployment guide](DOCKER.md).

## Requirements (non-Docker install)

- **Ubuntu Server** 22.04+ (tested on 22.04, 24.04) — Python 3.9+ required
- SSH key-based access to Cumulus switches
- Sudo privileges on target switches

## [00] quick start  

``` 
git clone https://github.com/aliaydemir/lldpq-src.git
cd lldpq-src
./install.sh 
```

## [01] what it does

- validates LLDP and monitors switches every 10 minutes
- collects bgp, optical, ber, link flap, hardware health data
- shows network topology with lldp
- auto-refreshing, generation-consistent web dashboard snapshots
- live network tables (MAC, ARP, VTEP, Routes, LLDP neighbors)
- tracepath: visual path tracing between any two IPs (intra-VRF, inter-VRF, external)
- device details page with command runner

## [02] analysis coverage

- **bgp neighbors**: state, uptime, prefix counts, health status
- **evpn summary**: VNI counts (L2/L3), Type-2/Type-5 route analysis
- **duplicate address detection**: duplicate IP/MAC detection via EVPN DAD + MAC-mobility sequences, with severity, quiesced/aged lifecycle, and per-port interface descriptions (see [02e])
- **optical diagnostics**: power levels, temperature, bias current, link margins  
- **link flap detection**: carrier transitions on all interfaces (including breakouts), with time-windowed flap counts (1h / 12h / 24h)
- **Link error / BER**: directional frame-error density from interface counters, plus separately graded raw/effective PHY BER and PHY symbol-error deltas
- **PFC/ECN**: telemetry-free per-port analysis of traffic-class 3 ECN
  marks, transmitted frames, unicast-buffer/WRED discards, and
  switch-priority 3 RX/TX pause frames. The first usable sample establishes a
  baseline; later samples show reset-safe deltas, average rates, ECN-mark
  percentage, and combined discard delta. Missing counters remain unavailable
  rather than becoming zero, and the page applies no arbitrary
  warning/critical thresholds.
- **hardware health**: cpu/asic temperatures, memory usage, fan speeds, psu efficiency
- **topology validation**: lldp neighbor verification against expected topology

### PFC/ECN report

The report distinguishes quiet, ECN, PFC, combined ECN+PFC, discard,
baseline, reset, missing-data, and collection-failure states. It includes a
Metric Guide, device/status/text filters, clickable summary filters, sortable
columns, and CSV export of the visible rows.

## [02b] fabric search (live queries)

access via web UI: `http://<server>/search.html`

### global search
- search IP or MAC across **all devices** at once
- **cross-reference**: IP → finds associated MAC, MAC → finds associated IP
- **bond expansion**: shows physical ports for bond interfaces
- **vxlan filtering**: excludes vxlan interfaces for real physical data
- **route best match**: shows how each VRF would route an IP (longest prefix match)
  - VRF-based grouping with colored badges
  - "No Route" indicator for VRFs without matching routes
  - Device consistency check (shows if all devices use same route)
  - Uses cached data for fast queries

### per-device tables

| Tab | Description | Data Source |
|-----|-------------|-------------|
| **MAC** | MAC address table | `bridge fdb show` |
| **ARP** | ARP/Neighbor table per VRF | `ip neigh show` |
| **VTEP** | Remote VXLAN tunnel endpoints with MAC, Type, State | `bridge fdb show \| grep dst` |
| **Routes** | Routing table with VRF tabs, ECMP paths, AD/Metric | `vtysh -c "show ip route vrf all"` |
| **LLDP** | LLDP neighbor discovery | `lldpctl -f json` |

### features
- real-time SSH queries to devices
- **VRF tabs** for route filtering (click to filter by VRF)
- **route best match**: when IP not found, shows best matching route per VRF
- sortable table columns (click headers)
- search/filter support
- CSV export for MAC/ARP tables
- parallel queries for "All Devices" mode
- **fast subnet search**: cached-only queries for subnet patterns (e.g. `192.168.64`)

## [02c] device details & command runner

access via web UI: `http://<server>/device.html`

### tabs
| Tab | Description |
|-----|-------------|
| **Overview** | Device info, uptime, model, serial, OS version |
| **Ports** | Interface status with speed, state, neighbors |
| **Optical** | SFP/QSFP diagnostics with power levels, temperature |
| **NVT** | Runs the read-only `nvt` helper with a 45-second timeout and displays a colorized interface summary: admin/oper state, speed, MTU, type, VLANs, VRF, LLDP neighbor/port, description, and IP addresses. It is loaded on first use and can be refreshed independently. |
| **BGP** | BGP neighbor status per VRF |
| **Logs** | Recent logs from syslog, FRR, switchd, NVUE |
| **Config** | Displays `nv config show -o commands`, `nv config show -o yaml`, or `nv config diff`, with live filtering and download support. |
| **Command Runner** | Interactive command runner with templates |
| **Capture** | Live packet capture (tcpdump) with PCAP download |
| **cl-support** | Generate diagnostic bundles for TAC support |

### command runner features
- **pre-built templates**: organized by category with color-coded icons
  - System & Hardware (green)
  - Interfaces & Ports (blue)
  - Layer 2 / Bridge (purple)
  - BGP & Routing (orange)
  - EVPN & VXLAN (teal)
  - EVPN MH / Bonds (pink)
  - MLAG / CLAG (indigo)
  - Logs & Debug (red)
- **interface selector**: dropdown with all switch interfaces
- **VRF selector**: query BGP/routes per VRF
- **bond selector**: view nv bond details, system bond details
- **custom commands**: run any allowed command on device
- **output display**: formatted command output with auto-scroll

### packet capture (tcpdump)
- **interface selection**: auto-populated dropdown including VLANs
- **filter presets**: common tcpdump filters (ICMP, ARP, LLDP, BGP, etc.)
- **live mode**: real-time packet output with polling
- **PCAP mode**: capture to file and download for Wireshark
- **duration/count controls**: configurable capture limits
- **cleanup**: automatic old PCAP cleanup, delete all PCAP button

### diagnostic bundle (cl-support)
- **background generation**: runs `cl-support -M -T0` in background
- **status polling**: real-time progress indicator
- **download/delete**: manage bundle files directly from UI
- **page exit warning**: prevents accidental navigation during generation

### security
- commands are allowlisted diagnostics, with tightly scoped packet-capture and
  capture/bundle cleanup operations
- switch configuration commands are blocked

> **Authorization:** Device Details—including NVT, Config, and Command
> Runner—is admin-only. Operators can use the shared monitoring and analysis
> views, but cannot open Device Details or execute device commands.

## [02d] tracepath

access via web UI: `http://<server>/tracepath.html`

trace the network path between any two IPs across the fabric. uses cached fabric-scan data for instant results.

### features
- **source/dest IP input** with separate VRF selectors and auto-detect
- **swap button** to reverse source ↔ destination
- **3 scenarios**: intra-VRF, inter-VRF (border leaf + external gateway), external destination
- **same-device detection**: local switching when source and dest are on the same leaf
- **ECMP link health**: shows up/down link counts on spine/core layers from LLDP data
- **VRF auto-correct**: if user selects wrong dest VRF, auto-corrects from ARP data
- **summary header**: source/dest IP, device, VRF, VRF path, hop count

### path visualization

| Scenario | Path Shown |
|----------|------------|
| **same-pod intra-VRF** | Leaf → Spine (ECMP) → Leaf |
| **cross-pod intra-VRF** | Leaf → Spine → Core → Spine → Leaf |
| **inter-VRF** | Source → Spines → Border Leaf → External GW → Border Leaf → Spines → Dest |
| **external dest** (8.8.8.8) | Source → Spines → Border Leaf → External Network → Dest |
| **same device** | Source Host → Leaf (local switching) → Dest Host |

### universal algorithms (no hardcoding)

all path discovery is based on graph analysis — no hardcoded hostnames, IPs, or naming patterns:

| Algorithm | Method |
|-----------|--------|
| **tier detection** | LLDP neighbor degree analysis + BFS from leaves |
| **pod detection** | shared spine set intersection |
| **border leaf detection** | default route nexthop signature majority analysis |
| **core detection** | cross-pod spine tier-2 neighbor bridging |
| **link health** | LLDP bidirectional link status counting |

works with any Clos topology: 2-tier (leaf-spine), 3-tier (leaf-spine-core), or N-tier.

## [02e] duplicate address detection

access via web UI: **Duplicate** menu (`/monitor-results/duplicate-analysis.html`)

The report correlates current FRR EVPN duplicate-address-detection (DAD)
output, EVPN mobility sequences, local FDB entries, IPv4 neighbor data,
interface descriptions, and recent FRR duplicate logs. IP/MAC findings are
grouped by their resolved VLAN identity and show the VNI when it is resolved.
If a VLAN mapping is unavailable, the analyzer can use the available VNI as
the grouping fallback; for an FDB-only MAC with no known VNI, the VLAN value
is also used as the VNI display fallback. APIPA findings are grouped only by
switch and VLAN.

### finding types

| Finding | Meaning |
|---------|---------|
| **Active IP duplicate** | A current authoritative FRR IP DAD row has a recent duplicate event or its EVPN sequence increased since the previous analysis sample |
| **Quiesced IP duplicate** | A current authoritative FRR IP DAD row is still present but is flat/old; after seven quiet days it is collapsed under **Show aged** |
| **Confirmed MAC conflict** | The same MAC is currently LOCAL on physical switch ports on at least two switches; bond/EVPN-MH attachment is excluded |
| **MAC DAD finding** | A current/latched FRR MAC DAD flag or recent FRR DAD event; a flag alone does not prove simultaneous owners |
| **Active MAC mobility** | A per-observer sequence delta meets the switch's configured DAD moves/window policy; the fallback policy is 5 moves / 180 seconds |
| **Historical mobility** | Below-threshold movement or an extreme but currently flat mobility sequence; shown separately and not counted as a confirmed MAC conflict |
| **Possible loop** | A MAC that is not currently DAD-flagged, is not a confirmed MAC conflict, and does not participate in a current authoritative IP-DAD finding is classified as a loop candidate when it spans at least two endpoints and ten active-mobility or confirmed-conflict signals share that VLAN and endpoint set |
| **APIPA / DHCP-failed** | IPv4 link-local (`169.254.0.0/16`) neighbors grouped per switch and VLAN; 50 or more in one switch/VLAN is critical |

### features

- shows local and contender `switch:port` locations with interface descriptions when available
- keeps current IP DAD, confirmed MAC conflicts, MAC DAD evidence, and MAC mobility as separate summary counters
- calculates MAC mobility deltas per observing switch and normalizes them against the configured moves/window policy
- treats counter resets and newly established baselines without creating negative deltas
- preserves short-lived IP owner-port context so fast-moving conflicts can still show both locations
- filters by summary card or device and hides aged findings by default
- the current **Download CSV** action exports the currently visible rows from the IP duplicate table
- the Thresholds dialog documents data sources, grading, EVPN-MH behavior, and targeted FRR DAD-clear commands

## [02f] Ask-AI (admin only)

Ask-AI combines the current collected fabric state with bounded, read-only
live checks. Responses can include an evidence panel with source freshness,
coverage, confidence, partial-result warnings, a time-bounded event timeline,
correlations, and the checks performed by the agent.

- **Analyze** performs an autonomous review of the previous 24 hours. A saved baseline is replaced only when collection is complete and current.
- Chat runs as a background job with live progress lines and a **Stop** button; long multi-round investigations are no longer bound by the request timeout.
- Suggested fixes open **Commands** prefilled for administrator review; Ask-AI never executes them automatically.
- Console suggestions can open the interactive Console for the selected device.
- `[AUDIT: <pack> <device|@role>]` runs a named read-only audit pack (`bgp`, `evpn`, `optical`, `mtu-path`, `pfc`, `hardware`) in one SSH session per device and prepends a deterministic verdict block to the evidence.
- Analysis findings carry **NEW** / **ONGOING** / **RESOLVED** badges (plus worsened/reopened) tracked across runs; a device missing from the current collection is never marked resolved.
- Known-benign findings can be acknowledged with `suppress: <device|*|@role> [CATEGORY] <regex> [ttl=7d] [because ...]` and removed with `unsuppress: <id or fragment>`. Suppressions expire on TTL and auto-reopen when the finding's severity worsens past the acknowledged level.
- Recent fabric changes (24h git log of the Ansible directory plus running-config drift) are correlated into analysis and change-related chat questions.
- Optional critical/error logs can be attached to the request.
- Persistent site facts can be saved in **Memory**, including with `remember: ...` or `hatırla: ...`; a fact can be removed with `forget: <fragment>`.
- Chats can be exported for later review.
- Supported providers include Ollama, Gemini, OpenAI, Claude/Anthropic, NVIDIA inference, and custom OpenAI-compatible endpoints. Provider settings include endpoint URL, API key, model, optional search model, and proxy.

> **Data handling:** When a cloud or custom provider is selected, the user
> question, bounded conversation history, relevant persistent Memory facts,
> supplied fabric context, and live-check results are sent to the configured
> endpoint. This can create privacy, data-egress, and usage-cost implications.
> Optional web search is used only when a search model is configured and the
> request calls for web research.

The autonomous analyzer is triggered after a successful full collection and
throttled to at most once per hour; it runs only when an AI provider and model
are configured. It is tiered: a cheap findings-only scan gates the full
synthesis call (skipped entirely when complete coverage is clean), and critical
findings trigger a targeted per-device drill-down. The scan stage uses
`AI_FALLBACK_MODEL` automatically when configured; single-model setups use
the same `AI_MODEL` for the scan — savings come from skipping calls, not from
requiring a second model. AI memory, analyses, and snapshots are stored under
`/var/lib/lldpq/ai`; Docker deployments should persist the
`lldpq-ai-state` volume.

Additional AI settings are read from `/etc/lldpq.conf` (the settings UI does
not expose them):

| Key | Purpose |
|-----|---------|
| `AI_FALLBACK_MODEL` | Secondary model tried automatically when the primary model call fails; also preferred for the hourly scan stage when set |
| `AI_CONTEXT_WINDOW_TOKENS` | Override the assumed context window (tokens) of the primary model |
| `AI_FALLBACK_CONTEXT_WINDOW_TOKENS` | Same override for the fallback model |
| `AI_SEARCH_URL` / `AI_SEARCH_KEY` | Separate endpoint and API key for the optional search model; they default to the main endpoint and its key when unset |

`AI_SEARCH_MODEL` and `AI_PROXY_URL` are also stored in `/etc/lldpq.conf` and
correspond to the search model and proxy fields in the settings UI.

Local/air-gapped deployments can use the Ollama provider fully offline: run a
current tool-capable local model and ensure its context length is large enough
for the supplied fabric context (compact prompts are used automatically for
local models).

## [02g] switch lifecycle and Analysis Scope

Administrators classify switches from **Provision → Handover** as either
`commissioning` or `handed_over`. This classification changes monitoring
views only: collection remains fabric-wide and `devices.yaml` is not modified.

Every authenticated user has an **Analysis Scope** selector with **All
Switches**, **Commissioning**, and **Handed Over** choices. The selection is
stored per browser tab. The Fabric dashboard always remains global. Scope
filtering applies to LLDP, BGP, Duplicate, Link Flap, Optical, BER, PFC/ECN,
Hardware, Logs, Assets, and Transceiver views; it does not narrow collection.
For LLDP, only the current `lldp.html` report is scoped; LLDP Problems and
Archive remain global.

Changing Analysis Scope never redirects to a separate lifecycle dashboard.
If a supported report is open, that report reloads in place so its rows,
summaries, selectors, and CSV export are recalculated. On Fabric, the selected
scope remains stored for later reports, but the dashboard stays unfiltered.
The former Commissioning/Handed Over monitoring overview has been retired;
**Provision → Handover** remains the admin-only workspace for viewing and
changing lifecycle classification.

Scoped CSV exports contain only matching switches. Global top-N anomaly
samples are hidden in scoped mode when a reliable scoped count cannot be
derived. If the selected scope cannot be verified, report data is hidden
rather than displayed unscoped.

## [02h] interactive Console (admin only)

The Console provides simultaneous interactive sessions to inventory devices
and the LLDPq host. It supports multiple tabs, session reattachment within the
browser session, search, copy buffer, session-log download, and sending
selected output to Ask-AI. A device can be opened directly with
`/console.html?target=<hostname>`.

> **Broadcast warning:** Broadcast sends the entered text and Enter
> immediately to every connected session, without a confirmation dialog. An
> empty value sends Enter. Disconnected sessions are skipped and reported.

> **Privilege warning:** Console is an unrestricted interactive shell, not the
> allowlisted Device Details command runner. Input is forwarded directly to a
> login shell or switch SSH PTY and can change the LLDPq host or a device with
> the connected account's privileges.

## [03] configuration files

edit these files:

```
~/lldpq/devices.yaml             # add your switches (required) - used by pping, zzh, send-cmd, get-conf
~/lldpq/tracking.yaml            # lifecycle state overrides and transition metadata
~/lldpq/topology.dot             # expected cable connections
~/lldpq/topology_config.yaml      # optional: customize device layers/icons (supports regex patterns)
~/lldpq/notifications.yaml        # optional: slack alerts + thresholds
~/lldpq/commands                 # optional: commands for send-cmd
```

### devices.yaml format

```yaml
defaults:
  username: cumulus

devices:
  10.10.100.10: Spine1            # simple: IP: Hostname
  10.10.100.11: Spine2 @spine     # with role: IP: Hostname @role
  10.10.100.12:                   # extended format
    hostname: Leaf1
    username: admin
    role: leaf
```

roles are optional tags for grouping. They are used for:
- **CLI filtering**: `zzh @spine`, `send-cmd -r leaf -c "uptime"`
- **Web UI grouping**: Device Details, Base Config deploy, and other pages group devices by role. Without roles, all devices appear in a single flat list which makes navigation harder on large fabrics.

Recommended roles: `leaf`, `spine`, `core`, `border`, `oob` (or any naming that fits your topology).

### tracking.yaml format

```yaml
version: 1
default_state: commissioning

switches:
  leaf-01:
    state: handed_over
    changed_at: "2026-07-07T10:30:00Z"
    changed_by: admin
    note: "Accepted by operations"
```

Valid states are `commissioning` and `handed_over`. Switches absent from this
file default to `commissioning`. The **Provision → Handover** workflow
maintains the transition metadata; this file does not define inventory.

### endpoint_hosts (optional)

add extra hostnames for topology visualization in devices.yaml. supports exact names and wildcard patterns:

```yaml
endpoint_hosts:
  - border-router-01      # exact hostname
  - "*dgx*"               # pattern - all devices containing "dgx"
  - "leaf-*"              # pattern - all devices starting with "leaf-"
  - "*-gpu"               # pattern - all devices ending with "-gpu"
```

patterns are matched against devices found in LLDP neighbor data.

## [03b] guided web setup (Setup page)

Admin-only **Setup** page (`http://<server>/setup.html`) — a guided, 11-step wizard that walks you through the whole lifecycle, from a fresh install to day-2 maintenance. A numbered rail shows the current step. Every step is also reachable directly with `setup.html?step=<name>`, while Next/Back follows the recommended order.

| # | Step | What it does |
|---|------|--------------|
| 1 | Inventory | Edit `devices.yaml` — switches & credentials |
| 2 | SSH Keys | Generate the collector key, authorize it on devices + passwordless sudo |
| 3 | Topology | Edit `topology.dot` — expected cabling |
| 4 | Topology Config | Edit `topology_config.yaml` — layout / layer / icon rules |
| 5 | Display Aliases | Optional — edit device/interface P2P and field display names |
| 6 | Integrate Ansible | Optional — point to the Ansible dir for VLAN/VRF/Fabric features |
| 7 | Notifications | Slack alerts — webhook, channel, alert types, thresholds, Test button |
| 8 | Run LLDPq | Collect data & validate, with live streaming output |
| 9 | Backup & Restore | Export / import a portable Setup configuration bundle |
| 10 | Maintenance | Disk-usage report & safe cleanup of old update backups |
| 11 | Update LLDPq | Online Git update or validated offline tarball update, with live output |

Step 8 also exposes the update-safe dashboard instance name. `LLDPQ_HOSTNAME`
defaults to `lldpq` and changes only the title above the main dashboard logo;
it does not modify the operating-system hostname. The value is stored in
`/etc/lldpq.conf`, survives native and Docker updates, and is included in the
portable Setup preferences.

### Display Aliases (step 5)

Edit `display-aliases.json` without leaving Setup. Device names and interface/port names are separate maps from canonical names to display labels. The editor supports structured rows, bulk paste (`display-label<TAB>canonical-name`), and JSON upload/download. Aliases affect presentation only; collected source data and topology validation remain unchanged.

The same alias editor remains available from the LLDP page. Saving either editor reloads the server-normalized mapping and notifies other open LLDPq tabs.

### Notifications (step 7)

Configure Slack alerting entirely from the web UI — no manual YAML editing:
- **Master enable/disable** toggle
- **Slack webhook URL** + channel
- **Alert mode** and minimum repeat interval for individual-alert strategies
- **Per-type toggles** for hardware, network, system, topology, and log alerts
- **Key thresholds** (temperature, link-flap count, …) editable inline
- **Test alert** button — sends a sample message to verify the webhook end-to-end

Changes are validated and written atomically; existing comments and unrelated YAML keys are preserved. If the file changes elsewhere while the form is open, Setup keeps the form contents and asks you to reload/review instead of silently overwriting the newer file.

### Backup & Restore (step 9)

Export a portable Setup configuration bundle (`.tar.gz`) and re-import it on
an installed LLDPq host. This is a configuration-migration bundle, not a
complete runtime or bare-metal backup.

- **Included:** `devices.yaml`, `tracking.yaml`, `topology.dot`, `topology_config.yaml`, `notifications.yaml`, `display-aliases.json`, and a whitelist of **portable** `/etc/lldpq.conf` preferences (schedules, parallelism, feature toggles, AI settings)
- **Excluded from portable prefs:** host-specific paths and secrets (e.g. the AI API key)
- **SSH key** (optional checkbox, on by default): includes the collector key pair so the restored install can reach devices immediately. Bundles can already contain notification webhooks; always store them securely, especially when the private key is included.
- **Not included:** monitoring/config history, DHCP leases and full DHCP configuration, uploaded OS images, generated provisioning files, LLDPq users/sessions, private Ask-AI analysis/learnings, or active job state.
- **Import** restores every file to the right location, merges the portable prefs into `/etc/lldpq.conf`, and applies any schedule changes to cron.
- **Transactional restore:** every included file is validated and staged before activation. Restore is all-or-rollback; native systemd recovery and Docker startup recovery consume retained rollback authority after an interruption.
- After a successful restore, run step 8 (**Run LLDPq**) to refresh derived data with the restored configuration.

### Maintenance (step 10)

- **Disk usage** report for `monitor-results/` and the old update backups, plus total free space
- **Safe purge** removes only completed `~/lldpq-backup-*` directories that
  contain a non-empty `COMPLETE` marker. These directories exist only when
  `./install.sh --backup` or the Setup **Take a full backup** checkbox was
  explicitly selected; ordinary updates do not create a permanent backup.
  The automatic update rollback snapshot is temporary and is removed after a
  successful update.

### Online and offline update (step 11)

The native online update uses the configured `LLDPQ_SRC` Git checkout, or
clones the public repository into the LLDPq service account's home when no
checkout exists. It requires access to `github.com` and passwordless `sudo` for
the LLDPq service account. nginx and fcgiwrap restart during installation, so
the page may disconnect briefly; the detached update continues and Setup
reconnects to its log.

For an air-gapped native host:

1. On a machine with internet access, download
   `https://aliaydemir.com/lldpq-src.tar.gz`.
2. Open **Setup → Update LLDPq → No internet on this host?**
3. Optionally select **Take a full backup**, choose the tarball, then click
   **Upload & update**.

The offline path validates archive paths, types, and size before extraction
and runs `install.sh` with `LLDPQ_OFFLINE_UPDATE=1`. It does not use apt, pip,
or GitHub; all required runtime dependencies must already be installed. Do not
manually extract an update archive over the live installation.

Both web update methods are for native installations. Docker images must be
updated from the Docker host using the [Docker update
procedure](DOCKER.md#updating).

### Uninstall LLDPq (Danger Zone)

Uninstall is deliberately **not** a numbered wizard step. It appears in a
separate Danger Zone after step 11 because a successful uninstall removes the
LLDPq nginx route, Setup API and web files; there is no next page for the
wizard to open. Losing the Setup connection after the detached uninstall has
started is therefore expected.

The web flow is available only for a native Linux installation. A Docker
container cannot remove its own host container, image or volumes, so Docker
deployments show host-side `docker compose down` / `docker rm` guidance instead
of running the native uninstaller.

Before the destructive action, Setup shows a side-effect-free dry-run. To
start the real operation, an admin must type `UNINSTALL` exactly and confirm a
second time. This uninstall API accepts only the root-owned gateway's fixed
`preview`, `start`, and `status` operations; uninstall options are bounded JSON
rather than caller-selected executable paths or command-line arguments.
The default **Keep selected data** option maps to `uninstall.sh --keep-data`.
It first copies the retained items into
`$LLDPQ_INSTALL_DIR/uninstall-kept-data/`, then removes their former live/web
locations. The retained set is exactly:

- Setup configuration: `devices.yaml`, `tracking.yaml`, `notifications.yaml`, `topology.dot`,
  `topology_config.yaml`, and `display-aliases.json`;
- runtime data: `monitor-results/`, `lldp-results/`, and `alert-states/`;
- history: collected `configs/`, command-history `hstr/`, and the web
  `monitor-results/` tree.

It does not retain `/etc/lldpq.conf`, LLDPq users/sessions,
generated/provisioning files, or `assets.ini`. Collector SSH keys in the
service user's `~/.ssh/` are outside the managed uninstall targets and remain
on disk regardless of this checkbox. Timestamped `~/lldpq-backup-*` snapshots
and data in separately configured Ansible/project directories are likewise
outside the uninstall targets. The native telemetry stack is stopped with its
Compose volumes removed even when selected data is kept.

The advanced **Remove the `LLDPQ_SRC` source checkout** option is independent
of the data choice and is off by default. When explicitly selected, the
dry-run shows the exact path plus its Git/working-tree state; the real uninstall
then removes that checkout, including Git history, committed files, local
changes and untracked files. Recursive removal is authorized by a root-owned
source identity written by the installer and is refused if the path, inode,
ownership, source layout or safety boundaries no longer match. In particular,
the checkout must be a strict child of the LLDPq service user's home and must
not overlap the home itself, the live install/web trees or configured external
project directories.

Normal native uninstall also removes LLDPq's dedicated transient/runtime
directories, including the service user's `~/.lldpq-state/`, `/var/lib/lldpq/`
and `/var/log/lldpq/`, plus the fixed Ansible CGI runtime roots
`/tmp/ansible-{www,tmp,cache}` and known LLDPq lock/state files under `/run`
and `/tmp`. Shared parent directories are not recursively removed. This
cleanup is separate from the retained-data copy described above and never
includes `~/.ssh/`, `~/lldpq-backup-*` or external Ansible/project data.

Optional package-removal controls are off by default and affect the whole
host, not just LLDPq: removing DHCP deletes the ISC DHCP configuration and
leases, removing nginx also removes fcgiwrap, and removing Docker purges the
Docker/containerd packages plus all data under `/var/lib/docker` and
`/var/lib/containerd`. Review the dry-run carefully before enabling any of
them. The partial-tree override (`--force-partial`) is intentionally not
exposed by the web UI.

The CLI and web flow execute the same `uninstall.sh` cleanup engine. Use a
dry-run first; interactive CLI confirmation also requires the exact word
`UNINSTALL`. To remove all LLDPq-owned data including the verified source
checkout, or to additionally purge the explicitly selected host-wide
dependencies, use:

```bash
./uninstall.sh --dry-run --remove-source
./uninstall.sh --yes --remove-source

# Also purge host-wide nginx/fcgiwrap, DHCP and Docker packages/data:
./uninstall.sh --yes --remove-source --remove-nginx --remove-dhcp --remove-docker
```

The host-wide flags remain independent and off by default because those
services and their data may be shared by workloads unrelated to LLDPq.

## [04] cron jobs (auto setup)

LLDPq owns a single `/etc/cron.d/lldpq` file. The default native-install
schedule is:

| Schedule | Job | Purpose |
|----------|-----|---------|
| `*/10 * * * *` | `lldpq` | complete monitoring pipeline and alert evaluation |
| `0 */12 * * *` | `get-conf` | configuration backup |
| `* * * * *` | `lldpq-trigger` | singleton daemon for web refresh requests |
| `* * * * *` | `lldpq-provision-scheduler` | discovery scheduling and upgrade resume |
| `* * * * *` + 30s | `fabric-scan.sh` | cached topology/search data; delayed so the full collector has lock priority |
| `0 0 * * *` | Git auto-commit | daily configuration-history commit |
| Post full collection, max hourly | `lldpq-ai-analyze --if-due` | autonomous AI analysis of the generation that just published |
| `33 3 * * *` | `fabric-scan-cron.sh` | optional Ansible diff check when Ansible is configured |

`LLDPQ_CRON` and `GETCONF_CRON` can override the first two schedules. Docker
installs run the operational jobs but omit native-host Git and optional
Ansible maintenance jobs. During an upgrade, only legacy entries that invoke
recognized LLDPq command paths or backup patterns are removed from
`/etc/crontab`.

Scheduled full collectors wait up to five minutes for an active cache-only
Fabric Scan, while manual duplicate invocations remain non-blocking. If an
older full collector publishes during that wait, the queued schedule is
discarded instead of starting a back-to-back duplicate generation.

The `lldpq-trigger` daemon processes token-specific LLDP validation and Assets
refresh jobs, full or page-scoped monitoring analysis, configuration
collection requests, and the separate on-demand transceiver firmware scan.
Failed LLDP, Assets, monitor, and configuration requests remain pending and
use bounded exponential retry. Transceiver scans use their own lock and
minimum interval.

## [05] update

`install.sh` handles both fresh install and updates automatically. It detects existing installations and runs in update mode:

```
cd lldpq-src
git pull                    # get latest code
./install.sh                # auto-detects: fresh install or update
```

Runtime monitoring data and user configuration are preserved automatically.
Every update also creates a temporary same-filesystem rollback snapshot of the
previous runtime plus critical system configuration. If a later DHCP, service
or cron step fails, the installer restores that snapshot automatically. It is
deleted after a successful update. A root-owned transaction marker and boot
recovery service cover SIGKILL, reboot and power-loss interruptions that cannot
run the installer's normal EXIT handler.

Before replacing Provision code, the updater also reconciles expired upgrade
records left by older LLDPq releases. It takes the scheduler/job locks, verifies
the current inventory and device identity, and uses read-only SSH evidence
(running ONIE process, installed version and deployment markers) before making
an old record terminal. The byte-exact original JSON is retained beside the
job as a timestamped backup. A recent, running, unreachable, malformed or
otherwise ambiguous upgrade still stops the update safely. Docker startup uses
the same check and promotes the previous release's fully validated resumable
job format to the current schema so an interrupted job can continue.
Recently completed pre-schema records are not delayed solely by a fixed safety
timer: the updater applies the same read-only live proof and converts a stale
timeout result when the target version and deployment markers are already
verified.

An optional, scoped recovery snapshot can be requested with
`./install.sh --backup` and is created at
`~/lldpq-backup-YYYY-MM-DD_HH-MM-SS/`. A `COMPLETE` marker is written only
after every requested copy succeeds; any copy failure aborts before the live
installation is stopped.

This directory is not a complete bare-metal image and cannot be uploaded to
the Setup portable-import form. It excludes `/var/lib/lldpq` sessions, private
Ask-AI state, and refresh/provision/upgrade job state. It does include
sensitive material such as `/etc/lldpq.conf`, password hashes, notification
webhooks, and SSH private keys; store it with restricted access.

### what gets backed up & preserved:
- **config files**: devices.yaml, tracking.yaml, notifications.yaml, topology.dot, topology_config.yaml
- **monitoring data**: assets.ini, monitor-results/, lldp-results/, alert-states/
- **system configs**: /etc/lldpq.conf, /etc/lldpq-users.conf
- **DHCP configs**: /etc/dhcp/dhcpd.conf, /etc/dhcp/dhcpd.hosts
- **provisioning state**: DHCP leases, ZTP/serial/display-alias settings,
  generated NVUE configs, uploaded OS images and ONIE aliases
- **SSH keys**: ~/.ssh/id_*
- **git history**: .git/ (config change tracking)

Use `./install.sh --help` for all options. Use `./install.sh -y` for non-interactive mode (CI/scripts).

If `/etc/dhcp/dhcpd.conf` already exists and was not generated by LLDPq, the
installer preserves it—even with `-y`. To replace it deliberately, use
`./install.sh --replace-dhcp-config`; the replacement requires a successful
`dhcpd -t` validation (and is refused if the validator is unavailable), then
the original is saved beside it as a timestamped
`.pre-lldpq-*.bak` file before activation.

The uninstaller can clean known system components from a partial installation
without recursively deleting an unrecognized install directory. After
verifying that guarded path manually, `./uninstall.sh --force-partial` also
removes the remaining partial tree.

## [06] requirements

- **Linux server** (Ubuntu 22.04+ recommended, tested on 22.04 and 24.04) — Python 3.9+ required
- **NVIDIA Cumulus Linux 5.x switches** with management IP access
- **SSH key auth** to all switches (setup via web UI — see [SSH Setup](#08-ssh-setup))
- All other dependencies (nginx, fcgiwrap, python3 ≥ 3.9, etc.) are installed automatically by `install.sh`
- **Python packages**: `python3-yaml` (PyYAML), `python3-ruamel.yaml` and `python3-requests` are required by the fabric/ansible backends — `install.sh` checks and installs them; on air-gapped systems install the OS packages manually before running it

## [07] disk usage

Monitor data grows ~50MB/day per fabric. Automatic cleanup keeps last 24 hours.

```
~/lldpq/monitor-results/     # ~50MB   analysis results (HTML reports)
~/lldpq/lldp-results/        # ~10MB   LLDP topology data
/var/www/html/configs/        # varies  device config backups (get-conf)
/var/www/html/hstr/          # ~5MB    historical data
```

## [08] ssh setup

### web UI (recommended — works in Docker too)

1. Login as admin → go to **Assets** page
2. Click the orange **SSH Setup** button
3. Enter device password (twice to confirm)
4. Click **Run Setup** — generates SSH key (if missing) + distributes to all devices + configures sudo
5. Results shown per device. Failed devices can be retried with a different password.

### CLI (bare metal install)

```
cd ~/lldpq && ./send-key.sh             # distributes SSH key + sets up passwordless sudo
cd ~/lldpq && ./send-key.sh --no-sudo   # key distribution only
cd ~/lldpq && ./send-key.sh --sudo-only # sudo setup only
cd ~/lldpq && ./send-key.sh -p "pass"   # non-interactive mode
```

## [09] cli tools

Inventory-aware tools default to `devices.yaml`; `pping` can also target one
IP or an explicit IP range directly.

```bash
# parallel ping
pping                              # ping all devices from devices.yaml
pping 192.168.1.10                 # ping one IP directly
pping 192.168.1.10 192.168.1.200   # ping an explicit same-/24 range
pping -r spine                     # ping only @spine devices
pping -r leaf -v mgmt              # ping @leaf via mgmt VRF
pping --roles                      # list available roles
pping -f /path/to/devices.yaml     # use custom devices.yaml
pping -h                           # show help

# send commands to devices
send-cmd                           # run commands from ~/lldpq/commands file
send-cmd -c "nv show system"       # run single command on all devices
send-cmd -c "uptime" -c "hostname" # run multiple commands
send-cmd -r spine -c "uptime"      # run only on @spine devices
send-cmd -r leaf -c "nv show bgp"  # run only on @leaf devices
send-cmd -f /path/to/devices.yaml -c "uptime"  # use a custom inventory
send-cmd --roles                   # list available roles
send-cmd -e                        # edit commands file
send-cmd -l                        # list commands file
send-cmd -h                        # show help

# ssh manager (ncurses UI)
zzh                                # interactive ssh manager
zzh spine                          # filter: show only "spine" in name
zzh @leaf                          # filter by role (from devices.yaml)
zzh -f /path/to/devices.yaml       # use custom devices.yaml
zzh -h                             # show help

# config backup
get-conf                           # backup configs from all devices (quiet)
get-conf -                         # backup configs from all devices and show output

# complete pipeline
lldpq                              # assets + outage pre-check + LLDP + monitor + fabric scan + alerts
lldpq -                            # same pipeline with visible output
lldpq -s                           # skip periodic optical DOM collection
lldpq - -s                         # visible output + skip periodic optical DOM collection

# direct/scoped monitoring
cd ~/lldpq && ./monitor.sh --help
cd ~/lldpq && ./monitor.sh --only bgp
cd ~/lldpq && ./monitor.sh --only duplicate
cd ~/lldpq && ./monitor.sh --only flap
cd ~/lldpq && ./monitor.sh --only optical
cd ~/lldpq && ./monitor.sh --only ber
cd ~/lldpq && ./monitor.sh --only pfc-ecn
cd ~/lldpq && ./monitor.sh --only hardware
cd ~/lldpq && ./monitor.sh --only logs
```

**Command safety:** `send-cmd` refuses high-impact commands such as `mlxlink`,
`onie-install`, reboot/shutdown, ZTP, and NVUE configuration
apply/replace/save operations by default. Set
`LLDPQ_ALLOW_DANGEROUS_COMMANDS=true` only for an explicit maintenance window.

A scoped `monitor.sh --only <scope>` run collects and regenerates only the
selected analysis. It uses the same global monitor lock as a full run, leaves
the full-pipeline manifest unchanged, and requires a current inventory plus a
recent successful full-run web baseline.

**Skip optical:** `lldpq -s`, `monitor.sh -s`, and `SKIP_OPTICAL=true` skip the
periodic `ethtool -m` DOM collection and optical report refresh. They do not
control transceiver firmware collection.

Transceiver firmware collection is a separate admin-only, on-demand `mlxlink`
scan from the **Transceiver** page. It is rate-limited to 30 minutes by
default, with 10 parallel workers and a 300-second SSH timeout by default.
SN2010, SN2100, SN2201, and SN2210 are always skipped for safety; devices with
an unknown model are skipped unless
`TRANSCEIVER_FW_UNKNOWN_MODEL_POLICY=run` is explicitly configured.

**L1 BER collection**: `SKIP_L1=false` is the default, so monitoring attempts
to collect `l1-show all -p` data for Physical BER, Effective BER, and PHY
symbol counters.
Set `SKIP_L1=true` only when intentionally trading those fields for a faster
collection cycle. The affected BER columns also show `N/A` when `l1-show` is
unavailable or its collection fails.

**Collection consistency and timeout behavior:** each switch's selected
monitoring data is collected through one SSH stream, validated as one complete
marker-delimited bundle, and staged before any per-device artifact is
replaced.

Failure handling depends on the failure type:

- malformed or truncated bundles are not activated; the previous valid device artifacts remain in place and the run is marked stale
- typed category-command failures publish explicit partial/unavailable coverage for that category while complete sections from the same device generation remain usable
- optical DOM port or collection-budget timeouts publish explicit unknown/partial optical coverage instead of silently omitting ports
- during a full run, if both SSH and the reachability check fail, old raw measurements are removed from the current generation and an explicit **Current collection unavailable** device page is produced; a scoped run preserves unrelated prior artifacts
- PFC/ECN port timeouts are represented in the new report as **Collection failed** or **Data missing**; unavailable counters are never shown as zero
- analyzer, validation, or web-publication failures roll analyzer state back and preserve the previous published reports

The following optional values tune bounded collection:

- `MONITOR_MAX_PARALLEL=100` — concurrent per-device collection workers
- `MONITOR_COMMAND_TIMEOUT_SECONDS=20` — timeout for otherwise-unbounded remote category commands (`1..120`)
- `PFC_ECN_MAX_PARALLEL=4` — concurrent per-port NVUE QoS reads on each switch (`1..8`)
- `PFC_ECN_COLLECTION_BUDGET_SECONDS=60` — QoS collection budget per switch
- `PFC_ECN_PORT_TIMEOUT_SECONDS=5` — timeout for one QoS read
- `OPTICAL_COLLECTION_BUDGET_SECONDS=120` — DOM collection budget per switch
- `OPTICAL_PORT_TIMEOUT_SECONDS=10` — timeout for one DOM read
- `MONITOR_TIMING=true` — emit per-device section timings

Verbose `lldpq -` runs also print one lightweight **Analyzer timings
(parallel)** block with the elapsed time of every analyzer. This is always
measured and does not require `MONITOR_TIMING`; normal `lldpq` runs remain
quiet. `MONITOR_TIMING=true` is the deeper diagnostic mode for per-device SSH,
bundle parsing, and individual collection-section timings.

The PFC/ECN analyzer additionally reports its load, record parsing, history
pruning, HTML rendering, and atomic-write subphases. Analyzer JSON artifacts
are fully parsed with a bounded parallel validator (two processes by default);
verbose output lists deterministic per-file validation timings. Any malformed,
missing, empty, or stale artifact remains fail-closed and rolls the analyzer
transaction back exactly as before.

The separate transceiver firmware scan uses
`TRANSCEIVER_FW_MIN_INTERVAL=1800`, `TRANSCEIVER_FW_MAX_PARALLEL=10`,
`TRANSCEIVER_FW_SSH_TIMEOUT=300`, and
`TRANSCEIVER_FW_UNKNOWN_MODEL_POLICY=skip` by default.

Bulk CLI defaults can be tuned with `SEND_CMD_MAX_PARALLEL=25`,
`GET_CONFIGS_MAX_PARALLEL=100` (the script fallback is 50 when the installed
setting is absent), and `GET_CONFIGS_SSH_TIMEOUT=60`.

## [10] authentication

web interface is protected with session-based authentication:

### default credentials:
```
admin / admin         # full access (includes Ansible Config Editor if configured)
operator / operator   # limited access
```

### features:
- **session-based login**: login page with 8-hour session timeout
- **remember me option**: stay logged in for 7 days
- **role-based access**: admin vs operator privileges
- **password management**: admin can change all passwords via UI
- **user management**: admin can create/delete operator users

### roles:

| Capability | Admin | Operator |
|---|:---:|:---:|
| View Fabric, LLDP, analysis, Assets, Configs, Logs, Search, Tracepath, Telemetry, and Topology | ✓ | ✓ |
| Select Analysis Scope | ✓ | ✓ |
| Run per-report analysis/collection actions | ✓ | — |
| Open Ask-AI, Device Details, Commands, or Console | ✓ | — |
| Use Setup, SSH Setup, Provision, or Handover changes | ✓ | — |
| Edit topology | ✓ | — |
| Access Ansible-backed reports or tools, when configured | ✓ | — |
| Manage users | ✓ | — |

Authorization is enforced server-side; hiding controls in the UI is not the
security boundary.

### user management (admin only):
1. login as admin
2. click username in sidebar
3. select "User Management"

**capabilities:**
- view all existing users and their roles
- create new users (automatically assigned "operator" role)
- delete users (except admin)
- deleted users are immediately logged out

**security rules:**
- new users can only be created with "operator" role
- admin user cannot be deleted
- users cannot delete themselves

### change passwords:
1. login as admin
2. click username in sidebar
3. select "Change Passwords"
4. choose user and set new password

**important**: change default passwords after installation!

## [11] alerts & notifications

get state-change alerts and scheduled health summaries via Slack.

### web UI (recommended)

The **Setup → Notifications** step (see [03b]) configures everything from the
browser: master and Slack enable/disable, webhook URL + channel, alert mode,
minimum repeat interval and per-type toggles for individual alerts, key
thresholds, and a **Test alert** button. Changes are validated and
written atomically while preserving existing comments and unrelated YAML
keys. In the default summary strategy, aggregate change/schedule rules apply
instead of individual-alert type toggles and minimum-repeat intervals.
Summary times are configured directly in `notifications.yaml`.

### manual (CLI)

```
cd ~/lldpq
nano notifications.yaml                               # add webhook URLs + enable alerts
python3 test_alerts.py                               # test configuration
```

### setup webhooks:

**slack:**  
1. go to https://api.slack.com/apps → create app → incoming webhooks
2. activate → add to workspace → choose channel → copy webhook url

### alert types:
- **hardware**: cpu/asic temp, fan failures, memory usage, psu issues
- **network**: bgp neighbors, excessive link flaps, optical health, and BER
- **system**: normalized 5-minute CPU load per core
- **topology**: LLDP validation mismatches
- **logs**: critical, error, and warning system log findings
- **duplicate**: authoritative active/quiesced IP-DAD counts and collection coverage
- **fabric availability**: total-fabric outage and recovery from current Assets reachability
- **recovery**: automatic notifications when issues resolve

### how it works:
- **smart detection**: individual alerts are stateful and deduplicated; the default summary mode also sends scheduled health summaries at its configured times (09:00 and 17:00 by default)
- **default 10-minute evaluation**: scheduled alerts run as part of the complete `lldpq` pipeline; a total-fabric outage/recovery pre-check runs after Assets collection, followed by the normal alert evaluation after monitoring reports are published
- **customizable**: adjust thresholds in notifications.yaml
- **state tracking**: prevents duplicate alerts, tracks recovery

Alerts start after both the master notifications switch and Slack are enabled
and a valid webhook is configured. Check `~/lldpq/alert-states/` for alert
history.

## [12] streaming telemetry

real-time telemetry dashboard with OTEL Collector + Prometheus (optional feature):

### installation options

**option 1: during install**
```bash
./install.sh
# Answer "y" to "Enable streaming telemetry support?"
```

**option 2: enable later (native install)**
```bash
./install.sh --enable-telemetry    # installs Docker, starts stack automatically
```

**disable — native install:**

```bash
./install.sh --disable-telemetry   # stops containers, removes volumes, updates config
```

**option 3: Docker deployment**

Docker deployments use a separate host-side telemetry stack and do not
require LLDPq container recreation. Follow the [Docker streaming telemetry
guide](DOCKER.md#streaming-telemetry) for bridge/host-network addressing,
persistent configuration, enable/disable, and metrics-retention behavior.

### workflow

| Action | Tool | What Happens |
|--------|------|--------------|
| Install stack (native) | CLI: `./install.sh --enable-telemetry` | Docker installed, stack started |
| Install stack (LLDPq in Docker) | Host workflow in `DOCKER.md` | Hardened separate telemetry stack started without recreating LLDPq |
| Enable on switches | Web UI: Enable Telemetry | Selected switches configured, metrics flow |
| Disable on switches | Web UI: Disable Telemetry | Selected switches unconfigured |
| Remove native stack | CLI: `./install.sh --disable-telemetry` | Containers, volumes, and metrics history deleted |
| Stop Docker-host stack | Host `docker compose stop` | Containers stop; metrics volumes remain |

### enable on switches

from the web UI (admin only):
1. go to **Telemetry** page (`http://<server>/telemetry.html`)
2. click **Configuration** tab → **Enable Telemetry**
3. enter your Collector IP (the server running OTEL)
4. select devices to configure (grouped by inventory, with real-time status)
5. click **Enable on Selected Devices**

**note**: operators can view the dashboard but cannot enable/disable telemetry.

### dashboard features
- **real-time metrics**: interface throughput, errors, drops
- **chart visualization**: time-series graphs with device filtering
- **top interfaces**: top 20 interface utilization ranking across fabric
- **AI ethernet stats**: TX wait, buffer utilization, pause frames, AR congestion, ECN marked packets
- **auto-refresh**: updates every 10 seconds

### available metrics
| Metric | Description |
|--------|-------------|
| Interface Stats | TX/RX bytes, packets, errors, drops |
| AI Ethernet Stats | TX wait, buffer utilization, pause frames, AR congestion, ECN marked packets |

### configuration files

Native installs use `~/lldpq/telemetry/`. The [Docker telemetry
procedure](DOCKER.md#streaming-telemetry) copies the same tree to
`$HOME/lldpq-telemetry/` on the Docker host:

```
telemetry-directory/
├── docker-compose.yaml           # container orchestration
├── config/
│   ├── otel-config.yaml           # OTEL Collector config
│   ├── prometheus.yaml           # Prometheus scrape config
│   ├── alertmanager.yaml         # notification config (edit for Slack/email)
│   └── alert_rules.yaml          # alert definitions
├── start.sh                      # management script
└── README.md                     # detailed setup guide
```

### lldpq.conf options

```bash
TELEMETRY_ENABLED=true              # feature enabled
PROMETHEUS_URL=http://localhost:9090 # Prometheus API endpoint
TELEMETRY_COLLECTOR_IP=192.168.1.100 # saved collector IP (auto-set)
TELEMETRY_COLLECTOR_PORT=4317        # saved collector port
TELEMETRY_COLLECTOR_VRF=mgmt         # saved VRF
```

### ports reference
| Service | Port | Description |
|---------|------|-------------|
| OTEL Collector | 4317 | OTLP gRPC (switches connect here) |
| OTEL Collector | 4318 | OTLP HTTP |
| Prometheus | 9090 | Web UI & API |
| Alertmanager | 9093 | Alert notifications |

### pre-configured alerts
- **InterfaceDown**: interface operationally down
- **HighInterfaceUtilization**: >80% for 5 minutes
- **HighInterfaceErrors**: >10 errors/sec for 5 minutes
- **HighPacketDrops**: >100 drops/sec for 5 minutes
- **BGPSessionDown**: BGP not in established state
- **HighCPUTemperature**: >85°C for 5 minutes
- **FanFailure**: fan status failure

### safe disable behavior

when disabling via web UI:
- only LLDPq telemetry config is removed from selected switches
- other telemetry configurations (if any) are preserved
- docker stack continues running (manage via CLI)
- metrics history is preserved

when disabling via CLI (`--disable-telemetry`):
- containers and volumes are completely removed
- all metrics history is deleted
- feature is marked as disabled

## [13] troubleshooting

```bash
# check if cron is running
cat /etc/cron.d/lldpq

# check if trigger daemon is running
ps aux | grep lldpq-trigger

# manual run
cd ~/lldpq && ./assets.sh && ./check-lldp.sh && ./monitor.sh

# check logs  
ls -la /var/www/html/monitor-results/

# check trigger logs
cat /tmp/lldpq-trigger.log

# check telemetry stack
cd telemetry && ./start.sh status

# test prometheus connection
curl 'http://localhost:9090/api/v1/query?query=up'
```

## [14] Provision (ZTP & Device Management)

Provision is an admin-only workspace for Zero Touch Provisioning and device
lifecycle management. It contains these tabs:

| Tab | Purpose |
|---|---|
| **Discover** | Scan a subnet for devices and run post-provision actions. |
| **Inventory** | Manage hostname, MAC, IP, serial, role, status, DHCP selection, and static bindings; import/export CSV and rebuild `devices.yaml`. |
| **Handover** | Classify switches as Commissioning or Handed Over without changing inventory or collection. |
| **DHCP Server** | Configure and inspect the DHCP service, static reservations, and logs. |
| **ZTP** | Manage the provisioning SSH key, quick settings, OS images, serial mappings, generated NVUE configs, and ZTP script. |
| **Upgrade** | Upgrade already-running switches with candidate discovery, prechecks, batching, verification, and queue controls. |
| **Base Config** | Deploy the standard base configuration files to selected devices. |
| **Guide** | Display the new-device provisioning workflow. |

### Discover Tab

The subnet scanner uses ping and SSH probes to classify devices:

| Device Type | How Detected |
|-------------|-------------|
| **Provisioned** | SSH key authentication works |
| **Not Provisioned** | SSH connects but the key is rejected |
| **Other** | The SSH probe is refused, times out, or otherwise does not complete successfully |
| **Unreachable** | No reachability evidence is found through ICMP, TCP/22, ARP, or SSH |

Additional indicators identify MAC mismatches and reachable addresses with no
inventory binding. Results load from a persistent cache; **Scan** starts an
immediate full scan. Automatic scanning is configurable as Off, 3, 5, 10, or
15 minutes, with 5 minutes as the default.

The Discover tab also owns the discovery IP range and the independent
post-provision toggles for Base Config, ZTP disable, and hostname assignment.

### Post-Provision Automation

Before any mutation, the scheduler verifies the responding device identity
against the Inventory record. The three optional actions have independent,
verified completion state:

| Action | Verified state on the switch |
|---|---|
| Deploy Base Config | `/etc/lldpq-base-config.sha256` matches the deployed manifest |
| Disable ZTP | `/etc/lldpq-ztp-disabled` and live ZTP state agree |
| Set hostname | `/etc/lldpq-hostname-target` and the running hostname match the inventory target |

The legacy `/etc/lldpq-base-deployed` marker remains compatible, but new work
does not rely on one aggregate marker. A later Base Config manifest change is
not silently rolled out by discovery; deploy it explicitly from **Base
Config**. Failed or unverifiable work stays visible for retry rather than
being marked complete.

### Inventory Tab

Inventory tracks planned and active device state, including hostname, MAC,
management IP, serial, role, status, and DHCP participation. Administrators
can add/edit/delete rows, bulk import or export CSV, inspect discovered MAC and
reachability, manage static DHCP bindings, and rebuild `devices.yaml` from the
eligible inventory rows. Active rows are written normally; planned rows are
retained as commented entries.

Placeholder MAC values can be used until the physical device is known. Saving
DHCP selections writes the guarded desired state; service activation remains
an explicit DHCP Server action.

### Handover Tab

Handover provides searchable and filterable lifecycle tracking with bulk
hostname selection. Administrators can preview and confirm moves in either
direction between Commissioning and Handed Over. The table records who
changed the state, when it changed, and an optional note.

Lifecycle changes update `tracking.yaml` only. They do not edit
`devices.yaml`, remove switches from collection, or narrow the global Fabric
dashboard.

To inspect either lifecycle group, choose it from
[Analysis Scope](#02g-switch-lifecycle-and-analysis-scope) and open a supported
analysis report. Provision no longer opens a separate Handed Over monitoring
page.

### DHCP Server Tab

Manage the DHCP server for automated IP assignment to new switches:

- **DHCP Configuration**: subnet, range, gateway, DNS, lease time, ZTP URL — all editable from web UI
- **Interface Selection**: dropdown with detected interfaces and their IPs
- **Static Reservations**: read-only view of the MAC-to-IP reservations currently rendered from `dhcpd.hosts`
- **Service Control**: Start / Restart / Stop buttons with live status indicator

Native installs can serve DHCP directly. Docker deployments must use the
explicit Linux host-network provisioning mode described in [Docker DHCP/ONIE
provisioning](DOCKER.md#dhcponie-provisioning); normal bridge-mode containers
keep DHCP disabled.

### ZTP Tab

Manage the Zero Touch Provisioning script (`cumulus-ztp.sh`):

- **SSH Key**: generate, import, or copy the public key used for provisioning
- **Quick Settings**: target OS version, default password, image server IP
- **Apply to Script**: auto-generates full ZTP template or updates existing script via regex
- **OS Image**: upload/delete Cumulus Linux `.bin`, `.img`, or `.iso` images for ZTP OS upgrades. When an OS upgrade is started, generic ONIE serving aliases (`onie-installer-x86_64`, `onie-installer-x86_64-mlnx`, `onie-installer`) are auto-created/refreshed in the web root pointing at the selected image, so ONIE's HTTP waterfall discovery finds it across Spectrum platforms
- **Serial Mapping**: map device serial numbers to inventory identity for ZTP
- **Generated Configs**: upload and synchronize generated per-switch NVUE YAML configurations
- **Script Editor**: collapsible Monaco-style editor with Reload/Save

The ZTP script handles: OS version check + upgrade, password change, sudo fix, SSH key installation.

### Upgrade Tab

Upgrade is intended for already-running Cumulus switches; ZTP remains the
workflow for new devices. Administrators select an uploaded target image,
target version, batch size, and candidate switches before running prechecks
and starting the persistent, resumable queue. The read-only image-server
address is inherited from **ZTP → Quick Settings**.

The workflow preserves each switch's `/etc/nvue.d/startup.yaml` during the OS
upgrade, verifies the installed version, and can optionally deploy Base Config
after verification. It can stop the queue on the first failure, cancel queued
work, and resume safely after service/container restart from persisted job
state.

### Base Config Tab

Deploy standard switch tools and configs to selected devices:

- **Device Selector**: grouped by role, with checkboxes, search, All/None
- **Files deployed**: `bash.bashrc`, `motd.sh`, `tmux.conf`, `nanorc`, `cmd`, `nvc`, `nvt`, `exa`
- **Parallel deploy**: 20 concurrent SSH/SCP workers
- **Progress table**: per-device OK/FAIL status
- **ZTP disable** option after deploy

### Full ZTP Workflow

```
New switch powers on
  → DHCP assigns IP (from dhcpd.conf + dhcpd.hosts bindings)
  → ZTP script runs automatically (cumulus-ztp.sh):
      - Check/upgrade OS version (onie-install if needed)
      - Change default password
      - Configure passwordless sudo
      - Install SSH public key
  → Discovery scan detects device:
      - Ping OK → reachable
      - SSH key auth OK → Provisioned
      - Verify serial/MAC/IP identity against Inventory
      - Run each enabled, incomplete post-provision action:
          - Deploy and verify Base Config manifest
          - Disable and verify ZTP state
          - Set and verify hostname target
  → Device fully configured, zero manual intervention
```

## [15] Ansible Integration

LLDPq's Ansible features (Fabric Editor, Fabric Config, Fabric Deploy) are designed for a
specific **Cumulus Linux NVUE automation structure**. They are not a generic Ansible UI.
The Ansible menu is automatically hidden when `$ANSIBLE_DIR` is not configured.

**Core LLDPq features (LLDP, monitoring, search, tracepath, telemetry, provisioning) work without Ansible.**

### Required Directory Structure

```
$ANSIBLE_DIR/
├── inventory/
│   ├── inventory.ini              # or hosts (INI format, standard Ansible)
│   ├── host_vars/                 # per-device YAML configs (standard Ansible)
│   │   ├── leaf-01.yaml
│   │   └── spine-01.yaml
│   └── group_vars/
│       └── all/
│           ├── sw_port_profiles.yaml   # port profile definitions
│           ├── vlan_profiles.yaml      # VLAN profile definitions
│           └── bgp_profiles.yaml       # BGP profile definitions
├── playbooks/
│   ├── diff_switch_configs.yaml                # compare running vs intended config
│   ├── deploy_switch_configs.yaml              # push config to devices
│   └── generate_switch_nvue_yaml_configs.yaml  # generate host_vars from templates
├── roles/       # optional (variable extraction for editor autocomplete)
└── templates/   # optional (Jinja2 template scanning)
```

### Feature Dependencies

| Feature | Required Files | Notes |
|---------|---------------|-------|
| Fabric Editor (file browser + git) | `$ANSIBLE_DIR` set | Works with any directory structure |
| Fabric Config (edit device configs) | `inventory/host_vars/{device}.yaml` | Standard Ansible layout |
| VLAN/Port profile management | `group_vars/all/vlan_profiles.yaml`, `sw_port_profiles.yaml` | See YAML key requirements below |
| BGP profile management + route leaking | `group_vars/all/bgp_profiles.yaml` | See YAML key requirements below |
| Diff (compare running vs intended) | `playbooks/diff_switch_configs.yaml` | Playbook name is hardcoded |
| Deploy (push config to device) | `playbooks/deploy_switch_configs.yaml` | Playbook name is hardcoded |
| Generate (create host_vars from templates) | `playbooks/generate_switch_nvue_yaml_configs.yaml` | Playbook name is hardcoded |
| VLAN/VRF/BGP reports | `group_vars/all/*.yaml` + `host_vars/` | Read-only analysis |

### YAML Key Requirements

The profile YAML files must use specific top-level keys and structures:

**`sw_port_profiles.yaml`** — top-level key: `sw_port_profiles`
```yaml
sw_port_profiles:
  SERVER_1G:
    speed: 1000
    mtu: 9216
    ...
```

**`vlan_profiles.yaml`** — top-level key: `vlan_profiles`
```yaml
vlan_profiles:
  TENANT_A:
    vlans:
      100:
        name: "Production"
        vrf: "VRF_A"
        ...
```

**`bgp_profiles.yaml`** — top-level key: `bgp_profiles`
```yaml
bgp_profiles:
  TENANT_A:
    enable_evpn: true
    peer_groups:
      External:                    # name "External" is auto-detected (no tag needed)
        description: "External-Connections"
        peers:
          10.0.0.1:
            description: "ISP-1"
            remote_as: 65000
      Upstream_BGP:                # custom name requires fabric_exit tag
        fabric_exit: true
        description: "WAN Uplinks"
        peer_type: external
        peers:
          10.0.0.5: {}
    ipv4_unicast_af:
      route_import:
        from_vrf:                  # route leaking structure
          - VRF_SHARED
  VxLAN_UNDERLAY_LEAF:             # profiles starting with "VxLAN_UNDERLAY" are filtered out
    ...
```

Key conventions used by LLDPq:
- **Fabric Exit peer groups** — shown on the Fabric Exit page for external BGP peer management. Two ways to mark a peer group:
  1. Name it `External` (auto-detected, no extra config needed)
  2. Add `fabric_exit: true` to any peer group with a custom name (e.g. `Juniper_Underlay`, `WAN_Peers`)
- Profiles prefixed with `VxLAN_UNDERLAY` — automatically excluded from user-facing lists
- `ipv4_unicast_af.route_import.from_vrf` — used for inter-VRF route leaking management
- The `fabric_exit` tag is ignored by Ansible — it only affects LLDPq's Fabric Exit UI

If these keys or structures differ in your Ansible repo, the corresponding UI features will not work correctly.

## [16] license

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

### What this means:
- ✅ **Free to use** for any purpose (personal, commercial, enterprise)
- ✅ **Modify and distribute** as you wish
- ✅ **No warranty** - use at your own risk
- ✅ **Only requirement**: Keep the original license notice

### Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

---

done.
