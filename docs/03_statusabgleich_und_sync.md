# 03. Statusabgleich & Shard-Sync (Spec 03)

> **Status:** Canonical Architecture Specification  
> **Topic:** Shard-Digest Pull, Status Queries, and Objective Lock State  
> **Related Documents:** [`03_routing_und_sharding.md`](03_routing_und_sharding.md), [`00_architektur_und_mental_model.md`](00_architektur_und_mental_model.md), [`06_dumb_server_smart_client_flow.md`](06_dumb_server_smart_client_flow.md)

---

## Objektiver Zustand statt Signatur-Archivierung (KISS-Prinzip)

Im HuMoCo Layer-2-Netzwerk gilt die strikte architektonische Trennung zwischen dem **flüchtigen Freigabe-Signal am Checkout** und dem **dauerhaften, schlanken Zustand im Shard-Register**.

```mermaid
flowchart TD
    subgraph HotPath["1. PoS Hot-Path Checkout (< 500 ms)"]
        direction TB
        Client["🛒 PoS / Wallet"] -->|"1. POST /v1/lock"| GW["🌐 Gateway"]
        GW -->|"2. LockVerifyRequest (parallel)"| Top20["🛡️ Top-20 Shard Nodes"]
        Top20 -->|"3. Atomic CAS in-RAM (< 1 µs)\nAttestation DTO"| GW
        GW -->|"4. 200 OK: QuorumCertificate\n(14/20 Signatures, ~896 B)"| Client
        Note1["Freigabe-Signal ('Grünes Licht'):\nReine Kassen-Quittung für den Händler.\nWird nach Checkout NICHT im Shard archiviert\nund NICHT in Folge-Transaktionen rekursiv mitgeführt!"]
    end

    subgraph ShardState["2. Objektiver Sperrzustand im Shard (Kollisionsregister)"]
        direction TB
        Top20 -->|"Asynchroner Flush"| Storage["RAM-Index + redb Key-Value\n• parent_lock (32B)\n• receiver_pub (32B)\n• nonce (variable)\n• id (32B)\n• valid_until (8B)"]
        Note2["Physische Schranke:\nDer Lock parent_lock -> child_lock im Shard ist\ndie physische Schranke gegen Double Spends.\nJeder spätere Versuch scheitert an der 409-Kollision im RAM."]
    end

    subgraph SyncAndQuery["3. Shard-Sync & Statusabfragen (Living Mesh)"]
        direction TB
        NewNode["🆕 Neuer / Recovernder Shard-Knoten"] -->|"ShardDigestRequest / ActiveSyncRequest"| Storage
        NewNode -->|"Übernimmt rein objektiven Zustand\n(0 Bytes Altsignaturen)"| LiveMesh["Autoritativer Shard-Knoten"]
        WalletQuery["📱 Statusabfrage (POST /v1/status)"] --> LiveMesh
        LiveMesh -->|"Quittiert & signiert Status live mit EIGENEM Schlüssel"| WalletQuery
    end

    HotPath --> ShardState
    ShardState --> SyncAndQuery
```

### 1. Das einmalige Freigabe-Signal am Checkout (Kassenpfad)
* **Zweck:** Das Quorum-Zertifikat (14 von 20 Ed25519-Signaturen, $\approx 896\,\text{Bytes}$) dient ausschließlich als flüchtiges Freigabesignal ("grünes Licht") an der Ladenkasse.
* **Händler-Sicherheit:** Es beweist dem Händler im Augenblick des Bezahlvorgangs, dass ein BFT-Quorum zuständiger Shard-Knoten die Unbedenklichkeit bestätigt und die Ausgabe auf `parent_lock` atomar registriert hat.
* **Kein rekursives Chaining & kein Mitschleppen:** Nach erfolgtem Checkout hat dieses historische Zertifikat für spätere Empfänger keinen Erkenntniswert mehr: Ein altes Quorum-Zertifikat beweist nicht, ob ein Gutschein *jetzt* noch unverbraucht ist (da in der Zwischenzeit ein Folgetransfer stattgefunden haben könnte). Folge-Transaktionen auf Layer 1 binden daher niemals historische L2-Quorum-Zertifikate rekursiv ein.

### 2. Der dauerhafte, schlanke Zustand im Shard (Kollisionsregister)
* **Physische Schranke:** Im Shard verbleibt lediglich der reine, objektive Datensatz: `parent_lock -> id` (zusammen mit `receiver_pub`, `nonce` und `valid_until`).
* **Unabhängigkeit von Altsignaturen:** Sobald ein Lock synchronisiert ist, scheitert jeder Double-Spend-Versuch deterministisch an der Kollisionsprüfung im RAM-Index ($< 1\,\mu\text{s}$) bzw. im persistenten `redb`-Speicher (`409 Conflict`) — völlig unabhängig davon, welche spezifischen Knoten ihn vor Monaten signiert haben oder ob diese Knoten überhaupt noch existieren.
* **Verfallszeit (TTL):** Der Zustand existiert exakt bis zum Ablauf der Gutschein-Wurzel (`root.valid_until` + 30s Grace-Period) und wird danach physisch aus RAM und Platte getilgt (*Zero State Bloat*).

### 3. Shard-Sync ohne Signatur-Müll (Anti-Bloat & KISS)
* **Reine Zustandssynchronisation:** Die deterministische Digest-Berechnung:
  $$\text{ShardDigest}(S) = \text{BLAKE3}\Big(0\text{x01} \mathbin{\Vert} \text{Shard\_ID} \mathbin{\Vert} \text{Lock}_1 \mathbin{\Vert} \dots \mathbin{\Vert} \text{Lock}_m\Big)$$
  hasht und vergleicht ausschließlich die Felder `parent_lock`, `receiver_pub`, `nonce` und `id` der aktiven Locks.
* **Ausschluss von Node-Attestierungen:** Historische Node-Signaturen oder 896-Byte-Quorum-Bündel sind im Digest **explizit nicht enthalten**. Würden Signaturen synchronisiert, würde das Datenvolumen pro Lock um ein Vielfaches explodieren, ohne jeglichen Sicherheitsgewinn für die Kollisionserkennung zu bieten.
* **Netzwerk-Schlankheit:** Über den Wire-Endpunkt `/v1/sync` bzw. QUIC `ActiveSyncRequest` werden reine `LockRecordDto`-Instanzen ausgetauscht.

### 4. Living Mesh statt Geisterknoten-Archivierung
* **Lebendige Autorität:** Neu hinzutretende oder nach einem Neustart synchronisierte Shard-Knoten übernehmen den objektiven Sperrzustand und werden sofort vollwertig handlungsfähig.
* **Eigene Quittierung:** Eingehende Statusabfragen (`POST /v1/status` oder QUIC `StatusQuery`) beantwortet und signiert der *aktuell* zuständige Shard-Knoten aus seinem synchronisierten Live-Zustand heraus mit seinem **eigenen, aktiven Ed25519-Schlüssel**.
* **Keine Totengräber-Bürokratie:** Das System vermeidet so die Abhängigkeit von veralteten Signaturen längst ausgeschiedener oder rotierter Vorgängerknoten ("Geisterknoten") und garantiert liveness-deadlock-freie Shard-Kontinuität.
