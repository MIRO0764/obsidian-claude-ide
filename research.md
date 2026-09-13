# Bezpečnostná analýza a audit zraniteľností

**Dátum auditu:** 13. september 2026  
**Projekt:** Obsidian Claude IDE (`claude-code-ide`)  
**Cieľ auditu:** Statická a architektonická analýza zdrojového kódu a závislostí projektu so zameraním na potenciálne bezpečnostné zraniteľnosti, slabiny v sieťovej komunikácii, úniky dát a stabilitu.

---

## 1. Manažérske zhrnutie

Projekt integruje Obsidian s CLI nástrojom Claude Code prostredníctvom lokálneho WebSocket servera na porte `127.0.0.1` a využíva lock súbory umiestnené v `~/.claude/ide/` na discovery a odovzdanie autorizačného tokenu (`authToken`).

Hoci architektúra správne obmedzuje sieťové rozhranie na `127.0.0.1` a vyžaduje vlastnú hlavičku `X-Claude-Code-Ide-Authorization`, audit odhalil niekoľko závažných zraniteľností a architektonických rizík:
1. **Denial of Service (DoS) / OOM pád** v dôsledku neobmedzeného buffera pri spracovaní WebSocket rámcov.
2. **Informačný únik (Information Disclosure)** tajného autorizačného tokenu v debug logoch.
3. **Riziko nechceného zmazania lock súboru iného vaultu** spôsobené logikou čistenia stale lockov.
4. **Zraniteľnosť závislosti `esbuild`** evidovaná v npm audit (GHSA-67mh-4wv8-2f99).
5. **Nedodržanie RFC 6455** pri absencii validácie maskovania klientskych WebSocket rámcov.

---

## 2. Prehľadná matica zraniteľností

| ID | Kategória / CWE | Názov | Závažnosť | Dotknuté súbory |
| :--- | :--- | :--- | :--- | :--- |
| **VULN-01** | CWE-400 / CWE-770 | Neobmedzený buffer a dĺžka WebSocket rámcov (DoS / OOM) | **Vysoká** | `src/server.ts`, `src/websocket.ts` |
| **VULN-02** | CWE-532 | Únik autentifikačného tokenu do debug logov | **Vysoká** | `src/server.ts` |
| **VULN-03** | CWE-377 / CWE-362 | Odstránenie lock súboru aktívneho sesterského vaultu | **Stredná** | `src/lock.ts` |
| **VULN-04** | GHSA-67mh-4wv8-2f99 | Zraniteľnosť vývojovej závislosti `esbuild <= 0.24.2` | **Stredná** | `package.json`, `package-lock.json` |
| **VULN-05** | RFC 6455 §5.1 | Akceptácia nemaskovaných rámcov z klienta | **Nízka** | `src/websocket.ts` |
| **VULN-06** | CWE-208 | Časovací únik pri porovnávaní autorizačného tokenu | **Nízka** | `src/server.ts` |
| **VULN-07** | CWE-1385 | Prístup k vlastnostiam prototypu pri dispatchingu RPC | **Nízka** | `src/tools.ts` |
| **VULN-08** | CWE-732 | Špecifiká súborových oprávnení na platforme Windows | **Nízka / Info** | `src/lock.ts` |
| **VULN-09** | CWE-78 | Nekontrolované načítanie `.env` v inštalačnom skripte | **Nízka / Info** | `scripts/install-plugin.sh` |

---

## 3. Detailný rozbor zraniteľností

### VULN-01: Neobmedzený buffer a dĺžka WebSocket rámcov (DoS / OOM)
* **Závažnosť:** Vysoká
* **CWE:** CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation of Resources Without Limits or Throttling)
* **Súbory:** `src/server.ts` (riadky 64–67), `src/websocket.ts` (riadky 39–57)
* **Popis problému:**
  V `src/server.ts` sú prichádzajúce TCP packety bez obmedzenia akumulované:
  ```ts
  socket.on("data", (data) => {
    client.buffer = Buffer.concat([client.buffer, data]);
    processFrames(client);
  });
  ```
  V `src/websocket.ts` parser akceptuje 64-bitové dĺžky:
  ```ts
  } else if (payloadLength === 127) {
    payloadLength = Number(buffer.readBigUInt64BE(2));
    offset = 10;
  }
  if (buffer.length < offset + payloadLength) return null;
  ```
  Ak klient pošle rámec s deklarovanou veľkosťou napríklad 8 GB, `parseFrame` opakovane vracia `null` (čaká na ďalšie bajty). Server neustále zreťazuje ďalšie bajty do pamäte, až kým proces nespadne na chybu alokácie pamäte v Node.js/Electrone.
* **Bezpečnostný dopad:**
  Pád celého Obsidian prostredia a strata neuložených údajov.
* **Odporúčaná náprava:**
  - Zaviesť konštantu `MAX_PAYLOAD_SIZE` (napr. 10 MB) a `MAX_BUFFER_SIZE` (napr. 15 MB).
  - Ak `payloadLength > MAX_PAYLOAD_SIZE` alebo `client.buffer.length > MAX_BUFFER_SIZE`, okamžite poslať WebSocket Close rámec s kódom `1009` (Message Too Big) a socket ukončiť (`socket.destroy()`).

---

### VULN-02: Únik autentifikačného tokenu do debug logov
* **Závažnosť:** Vysoká
* **CWE:** CWE-532 (Insertion of Sensitive Information into Log File)
* **Súbor:** `src/server.ts` (riadok 35)
* **Popis problému:**
  V handleroch WebSocket handshakeu je nasledujúce logovanie:
  ```ts
  if (headers["x-claude-code-ide-authorization"] !== options.authToken) {
    log("debug", "auth FAIL, expected:", options.authToken, "got:", headers["x-claude-code-ide-authorization"]);
    socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
    socket.destroy();
    return;
  }
  ```
  V neprodukčnom režime alebo pri zapnutom ladiacom výpise (`DEBUG = true`, resp. `obsidian dev:debug on`) sa pri každom neplatnom pokuse o pripojenie zapíše do konzoly očakávaný tajný kľúč.
* **Bezpečnostný dopad:**
  Útočník alebo lokálne bežiaci skript, ktorý sondou vyvolá 401 Unauthorized, môže následne z konzoly/logov Obsidianu získať platný `authToken` a plnú kontrolu nad RPC rozhraním pluginu.
* **Odporúčaná náprava:**
  Odstrániť `options.authToken` z ladiacej správy:
  ```ts
  log("debug", "auth FAIL: invalid authorization token");
  ```

---

### VULN-03: Odstránenie lock súboru aktívneho sesterského vaultu
* **Závažnosť:** Stredná
* **CWE:** CWE-377 (Insecure Temporary File), CWE-362 (Race Condition)
* **Súbor:** `src/lock.ts` (riadky 101–116)
* **Popis problému:**
  Funkcia `cleanStaleLockFiles` vyhodnocuje lock súbory nasledovne:
  ```ts
  if (lockFile.status === "foreign") continue;
  if (lockFile.status === "corrupt") throw new Error("corrupt lock");
  if (lockFile.pid === process.pid) throw new Error("own stale lock");
  process.kill(lockFile.pid, 0); // throws if dead
  ```
  Ak používateľ otvorí v Obsidiane druhý vault (alebo viacero okien zdieľajúcich hlavný proces), nová inštancia vidí existujúci lock súbor s `lockFile.pid === process.pid`. Považuje ho za svoj vlastný neaktuálny zámok, vyhodí chybu a v `catch` bloku ho zmaže:
  ```ts
  try {
    unlinkSync(lockPath);
  } catch {}
  ```
* **Bezpečnostný dopad:**
  Nechcené zrušenie prepojenia Claude Code s aktívnym vaultom a znefunkčnenie práce.
* **Odporúčaná náprava:**
  - Pred vymazaním locku overiť, či port skutočne neodpovedá (napr. krátkym TCP probe connectom).
  - V lock súbore uchovávať aj identifikátor vaultu alebo portu a overiť, či nie je obsadený aktuálne inicializovaným serverom.

---

### VULN-04: Zraniteľnosť vývojovej závislosti `esbuild <= 0.24.2`
* **Závažnosť:** Stredná
* **Advisory:** GHSA-67mh-4wv8-2f99
* **Súbory:** `package.json`, `package-lock.json`
* **Popis problému:**
  Balík `esbuild` vo verzii `^0.24.0` (nainštalovaný `0.24.0`) obsahuje bezpečnostnú chybu, ktorá umožňuje webovým stránkam pristupovať k odpovediam interného vývojového servera.
* **Bezpečnostný dopad:**
  Nízky pre konečných používateľov pluginu (keďže `main.js` je distribuovaný ako zbalený bundle a `esbuild` sa nespúšťa cez `--serve`), avšak z hľadiska hygieny dodávateľského reťazca (supply chain) ide o zraniteľnosť odhaliteľnú auditnými nástrojmi.
* **Odporúčaná náprava:**
  Aktualizovať balík príkazom:
  ```bash
  npm install --save-dev esbuild@^0.25.0
  ```

---

### VULN-05: Akceptácia nemaskovaných rámcov z klienta (RFC 6455 §5.1)
* **Závažnosť:** Nízka
* **Súbor:** `src/websocket.ts` (riadky 44–58)
* **Popis problému:**
  Špecifikácia WebSocket RFC 6455 vyžaduje, aby klientske rámce boli vždy maskované 4-bajtovým kľúčom. Server musí spojenie okamžite ukončiť, ak príde nemaskovaný rámec. Implementácia v `parseFrame` akceptuje aj `masked === false`.
* **Bezpečnostný dopad:**
  Potenciálna zraniteľnosť voči cache-poisoningu na úrovni reverzných proxy alebo sieťových sprostredkovateľov.
* **Odporúčaná náprava:**
  ```ts
  if (!masked) {
    // RFC 6455 §5.1 mandate
    return null; // resp. označiť protokolovú chybu a ukončiť spojenie kódom 1002
  }
  ```

---

### VULN-06: Časovací únik pri porovnávaní autorizačného tokenu
* **Závažnosť:** Nízka
* **CWE:** CWE-208 (Observable Timing Discrepancy)
* **Súbor:** `src/server.ts` (riadok 34)
* **Popis problému:**
  Porovnanie `headers["x-claude-code-ide-authorization"] !== options.authToken` prebieha cez bežný JavaScriptový operátor `!==`, ktorý porovnáva znak po znaku a pri prvej nezhode skončí skôr.
* **Bezpečnostný dopad:**
  Teoretická možnosť postupného odhadovania tokenu meraním odozvy spojenia (hoci na rozhraní `127.0.0.1` je sieťový šum zvyčajne vyšší než časový rozdiel).
* **Odporúčaná náprava:**
  Použiť kryptograficky bezpečné porovnanie:
  ```ts
  import { timingSafeEqual } from "node:crypto";

  function safeCompare(a: string, b: string): boolean {
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);
    if (bufA.length !== bufB.length) return false;
    return timingSafeEqual(bufA, bufB);
  }
  ```

---

### VULN-07: Prístup k vlastnostiam prototypu pri dispatchingu RPC
* **Závažnosť:** Nízka
* **CWE:** CWE-1385
* **Súbor:** `src/tools.ts` (riadky 156–160)
* **Popis problému:**
  ```ts
  default: {
    if (name in STUB_HANDLERS) {
      return toolResult(STUB_HANDLERS[name]());
    }
    return null;
  }
  ```
  Operátor `in` overuje existenciu kľúča aj v `Object.prototype`. Ak príde RPC požiadavka s `name: "__proto__"`, pokus o vykonanie objektu ako funkcie zlyhá na `TypeError`. Ak príde `name: "toString"`, vykoná sa prototypová metóda.
* **Odporúčaná náprava:**
  Použiť `Object.hasOwn(STUB_HANDLERS, name)` alebo vytvoriť tabuľku handlerov bez prototypu:
  ```ts
  const STUB_HANDLERS: Record<string, () => object> = Object.create(null);
  ```

---

### VULN-08: Špecifiká súborových oprávnení na platforme Windows
* **Závažnosť:** Nízka / Informatívna
* **CWE:** CWE-732 (Incorrect Permission Assignment for Critical Resource)
* **Súbor:** `src/lock.ts` (riadky 65–76)
* **Popis problému:**
  Parameter `{ mode: 0o600 }` v `writeFileSync` na operačnom systéme Windows nemá účinok na prístupové práva (ACL) jednotlivých používateľov; ovplyvňuje len atribút len na čítanie (read-only). Bezpečnosť lock súboru na Windows tak závisí výlučne od ACL rodičovského priečinka profilu (`C:\Users\<user>\.claude\ide`). Zároveň pri zlyhaní procesu pred premenovaním môžu v priečinku zostať nečistené súbory `.lock.tmp`.
* **Odporúčaná náprava:**
  Zahrnúť vzor `*.lock.tmp` do čistiacej procedúry `cleanStaleLockFiles`.

---

### VULN-09: Nekontrolované načítanie `.env` v inštalačnom skripte
* **Závažnosť:** Nízka / Informatívna
* **CWE:** CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
* **Súbor:** `scripts/install-plugin.sh` (riadok 13)
* **Popis problému:**
  Príkaz `source "$ENV_FILE"` spúšťa celý obsah súboru `.env` v shellovom interpreti. Ak by súbor obsahoval vložené shellové príkazy (napr. prevzaté z nedôveryhodného zdroja), dôjde k ich okamžitému vykonaniu.
* **Odporúčaná náprava:**
  Parsovať len konkrétnu premennú `OBSIDIAN_VAULT` bez plného vykonávania shell skriptu.

---

## 4. Odporúčaný akčný plán nápravy

1. **Fáza 1 (Okamžitá oprava):**
   - Odstrániť výpis `authToken` zo súboru `src/server.ts`.
   - Zaviesť maximálny limit na veľkosť WebSocket rámca a buffera v `src/server.ts` a `src/websocket.ts`.
2. **Fáza 2 (Stabilita a čistota kódu):**
   - Upraviť `cleanStaleLockFiles` v `src/lock.ts`, aby nedochádzalo k mazaniu lockov sesterských vaultov.
   - Nahradiť operátor `in` za `Object.hasOwn` v `src/tools.ts`.
   - Vynútiť klientske maskovanie rámcov v `src/websocket.ts`.
3. **Fáza 3 (Závislosti a hardening):**
   - Aktualizovať balík `esbuild` v `devDependencies`.
   - Implementovať `crypto.timingSafeEqual` pri overovaní tokenov.

