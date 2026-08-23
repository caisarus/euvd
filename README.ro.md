# euvd-watch

**Toolkit nativ EUVD pentru supravegherea vulnerabilităților din lanțul de aprovizionare software + raportare conform EU Cyber Resilience Act (CRA).**

> ✅ **Status: stabil — `1.0.0` este lansat.** Contractul CLI (comenzi, flag-uri, coduri
> de ieșire), schemele JSON pentru findings/VEX/CRA și formatul fișierului de configurare
> sunt acoperite de versionare semantică: schimbările incompatibile cer un salt de
> versiune majoră, iar deprecierile sunt anunțate cu cel puțin o versiune minoră înainte.
> Tabelul de comenzi de mai jos marchează ce este **✅ disponibil azi** față de **🧪
> beta**. Singura excepție de la promisiunea de stabilitate este dashboard-ul
> (`web serve`): complet implementat — aplicația, gate-ul de accesibilitate și un ghid de
> desfășurare testat (`docs/deploy.md`) — dar **beta**, pentru că suprafața se mai poate
> schimba înaintea versiunii `1.1` GA.
>
> *Această traducere urmează [README-ul în engleză](README.md); în caz de divergență,
> versiunea engleză este cea de referință.*

`euvd-watch` conectează transparența lanțului de aprovizionare software la **infrastructura
europeană de vulnerabilități** și la obligațiile concrete de raportare din **EU Cyber
Resilience Act**.

Ingerează **SBOM-ul** tău, corelează continuu fiecare componentă cu **European Union
Vulnerability Database (EUVD)** operată de ENISA — inclusiv marcajul *actively exploited*
și scorurile EPSS — redactează automat declarații **VEX** machine-readable pentru a reduce
zgomotul de false-positive-uri, iar când o componentă este lovită de o vulnerabilitate
exploatată activ, **redactează draftul notificării CRA Articolul 14 și pornește ceasul de
24 de ore**, cu un jurnal de audit tamper-evident.

## De ce există

Generarea SBOM (Syft, cdxgen) și scanarea contra surselor americane (NVD, OSV) sunt mature. Dar:

- **Nimic open-source nu e construit în jurul EUVD** — baza de date europeană de vulnerabilități, operată de ENISA.
- **Nimic nu leagă statusul „exploited" de fluxul real de raportare CRA** (avertizarea timpurie de 24 h către ENISA/CSIRT-uri).
- **Generarea VEX e încă în mare parte manuală**, așa că echipele se îneacă în finding-uri neaplicabile.

`euvd-watch` umple acest gol ca **piesă self-hostable** care rulează în CI/CD și programat.
**Nu** reinventează generatoarele de SBOM sau scanerele — le refolosește.

## Pipeline

```mermaid
flowchart LR
    A[SBOM<br/>CycloneDX / SPDX] -->|ingest| B[Componente<br/>normalizate]
    B -->|match| C[EUVD<br/>exploited + EPSS + KEV]
    C --> D[Declarații<br/>OpenVEX]
    C -->|trigger| E[CRA Articolul 14<br/>draft + ceas 24h + audit log]
    B -.->|CI/CD · CLI · watch| F[Dashboard]
```

## Pornire rapidă (tot ce e mai jos funcționează azi)

```bash
pip install euvd-watch
euvd-watch version

# 1. Generează un SBOM pentru proiectul tău (cu Syft, sau adu-l pe al tău)
syft dir:. -o cyclonedx-json > sbom.cdx.json

# 2. Vezi ce conține
euvd-watch scan sbom.cdx.json

# 3. Corelează-l cu EUVD — arată doar vulnerabilitățile exploatate activ
euvd-watch match sbom.cdx.json --exploited-only

# 4. Generează declarații OpenVEX (conservatoare prin design)
euvd-watch vex generate sbom.cdx.json -o openvex.json

# 5. Verifică dacă ceva a depășit pragul tău de raportare CRA
euvd-watch cra check sbom.cdx.json
euvd-watch cra status

# 6. Urmărește programat - notifică doar finding-urile noi/rezolvate/schimbate
euvd-watch watch sbom.cdx.json --interval 6h
```

## Comenzi

| Comandă | Status | Ce face |
|---|---|---|
| `scan <sbom>` | ✅ | Parsează și normalizează un SBOM **JSON** CycloneDX (1.4–1.6) / SPDX (2.3) într-un inventar de componente. |
| `match <sbom>` | ✅ | Corelează componentele cu EUVD, cu scor de încredere și îmbogățire EPSS/KEV. Flag-uri: `--exploited-only`, `--min-confidence`, `--fail-on`, `--no-enrich`, `--save-findings`, `--timestamp`. |
| `vex generate <sbom>` | ✅ | Redactează declarații OpenVEX. Doar finding-urile probabil sigure devin `not_affected`; tot ce e incert rămâne `under_investigation`. Îmbină `vex-decisions.yaml` (`--fail-on-conflict` pentru CI). |
| `vex init-decisions <sbom>` | ✅ | Generează scheletul unui `vex-decisions.yaml` din finding-urile curente, pentru completare umană. |
| `cra check <sbom>` | ✅ | Evaluează trigger-ul configurabil de raportare (EUVD exploited / CISA KEV / prag EPSS) și deschide evenimente. Iese cu `1` când se deschide un eveniment **nou**; iese cu `3` **indeterminat** când sursa unui semnal necesar (KEV/EPSS) a fost indisponibilă, deci un rezultat curat nu poate fi de încredere (vezi `docs/cra.md`). |
| `cra status` / `cra draft <id>` / `cra mark <id>` | ✅ | Urmărește ceasurile pe stagii (24 h / 72 h / raport final), redă un draft de notificare precompletat cu marcaje `TODO-HUMAN`, înregistrează finalizarea umană. |
| `cra verify-log` | ✅ | Verifică jurnalul de audit tamper-evident (hash-chained); numește prima intrare ruptă. |
| `watch <sbom>` | ✅ | Re-corelează programat (`--interval 6h`) sau o singură dată (`--once`, implicit) și notifică **doar finding-urile noi/rezolvate/schimbate** (stdout, și `--webhook URL`). Vezi `docs/watch.md`. |
| `db migrate` | ✅ | Aplică migrările de schemă pe baza de date de stare consolidată (`state_dir/euvd-watch.sqlite`) și importă fișierele de stare pre-0.4. Rulează transparent la fiecare comandă care atinge starea; comanda o face explicit. Vezi `docs/storage.md`. |
| `web serve` | 🧪 beta (țintă `1.1`) | Dashboard self-hostable: finding-uri, statusuri VEX, countdown-uri CRA, audit log, o singură acțiune de scriere protejată prin parolă. `web hash-password` generează credențiala. WCAG 2.1 AA verificat în CI; desfășurare Docker Compose + Caddy în `docs/deploy.md`. Vezi `docs/web.md`. |

Toate comenzile implementate suportă `--output json|table` și coduri de ieșire prietenoase
cu CI (`0` curat, `1` finding-uri, `2` eroare; `cra check` adaugă `3` indeterminat).
Comenzile neimplementate ies cu `2` și un mesaj clar.

## Folosire în CI

GitHub Action-ul (`action.yml` în rădăcina repo-ului), template-ul include pentru GitLab
(`templates/euvd-watch.gitlab-ci.yml`) și imaginea Docker (`docker/Dockerfile`) sunt
implementate, validate pe schemă și folosite chiar de CI-ul acestui repo — referința
completă e în `docs/integrations.md`.

GitHub Actions:

```yaml
- uses: anchore/sbom-action@v0          # generează SBOM cu Syft
  with: { format: cyclonedx-json, output-file: sbom.cdx.json }
- uses: caisarus/euvd@v0.4.1
  with:
    sbom-path: sbom.cdx.json
    fail-on: exploited
```

GitLab CI:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/caisarus/euvd/main/templates/euvd-watch.gitlab-ci.yml'

euvd-watch:
  variables: { EUVDWATCH_SBOM: "sbom.cdx.json", EUVDWATCH_FAIL_ON: "exploited" }
```

Docker (`ghcr.io/caisarus/euvd-watch`, sau build local):

```bash
docker run --rm -v "$PWD:/work:ro" ghcr.io/caisarus/euvd-watch:latest match /work/sbom.cdx.json
# sau build dintr-o clonă:
docker build -f docker/Dockerfile -t euvd-watch .
```

## Configurare

`euvd-watch.yaml` (sau `--config`, sau variabile de mediu `EUVD_WATCH_*`):

```yaml
cache_dir: ~/.cache/euvd-watch
epss_threshold: 0.5
min_confidence: medium
organization:
  name: "Example S.R.L."
  contact_email: security@example.com
  product_name: "Example Product"
cra_trigger:
  euvd_exploited: true
  cisa_kev: true
  epss_over_threshold: true
```

## Principii de design

- **Refolosește, nu reinventa** — împachetează output-ul Syft/cdxgen, OpenVEX, EPSS, KEV; construiește doar liantul lipsă.
- **EUVD pe primul loc**, cu OSV/KEV/EPSS ca suplimente.
- **VEX conservator** — nu suprima automat niciodată ceva ce ar putea fi risc real.
- **Raportare cu omul în buclă** — `euvd-watch` redactează; un om confirmă înainte ca orice să fie depus. Tool-ul nu trimite nimic automat, niciodată.
- **Auditabil** — fiecare decizie poartă o explicație pe înțelesul oamenilor și ajunge într-un jurnal de audit hash-chained.
- **Determinist** — aceleași intrări produc ieșiri identice byte-cu-byte.

## Ce NU este euvd-watch

- Nu e generator de SBOM (folosește Syft/cdxgen).
- Nu înlocuiește un scaner general (Grype/Trivy rămân excelente pentru acoperirea NVD/OSV).
- Nu e consultanță juridică și nu e un instrument de depunere automată — notificările CRA
  sunt întotdeauna verificate și transmise de un om, prin canalele oficiale.

## Arhitectură & documentație

📖 **Tot ce urmează poate fi citit, căutat și navigat și la
<https://caisarus.github.io/euvd/>.**

**Începe de aici**

- [GLOSSARY.ro.md](GLOSSARY.ro.md) — fiecare termen tehnic (SBOM, VEX, CRA, EPSS…)
  explicat pe înțelesul oricui **(română)**
- [ARCHITECTURE.md](ARCHITECTURE.md) — cum se leagă piesele între ele, modul cu modul *(engleză)*
- [README.simple.md](README.simple.md) — aceeași poveste, explicată pe înțelesul unui copil *(engleză)*
- [GLOSSARY.md](GLOSSARY.md) — glosarul, în engleză

**Cum se comportă fiecare parte** *(engleză)*

- [docs/matching.md](docs/matching.md) — strategii de matching & scor de încredere
- [docs/cra.md](docs/cra.md) — fluxul CRA Articolul 14, stagiile de termene și modelul
  onest de amenințări al jurnalului de audit
- [docs/euvd-api.md](docs/euvd-api.md) — suprafața API EUVD verificată pe care o folosește tool-ul
- [docs/watch.md](docs/watch.md) — re-matching programat, diff și livrare prin webhook
- [docs/web.md](docs/web.md) — dashboard-ul, modelul de autentificare și limitele lui documentate
- [docs/storage.md](docs/storage.md) — baza de date de stare, migrările și backup-urile

**Rulare în producție** *(engleză)*

- [docs/integrations.md](docs/integrations.md) — GitHub Action, template GitLab, Docker
- [docs/deploy.md](docs/deploy.md) — self-hosting cu Docker Compose și Caddy
- [docs/accessibility.md](docs/accessibility.md) — gate-ul WCAG 2.1 AA și cum se rulează
- [docs/release.md](docs/release.md) — politica de versionare și procesul de release

## Contribuții

Contributorii timpurii sunt foarte bineveniți — vezi [CONTRIBUTING.md](CONTRIBUTING.md)
*(engleză)* pentru setup, rularea testelor și cele două reguli de guvernanță care țin
tool-ul onest: orice bug real devine un rând în tabelul de adevăr **înainte** ca fix-ul
să intre, iar orice intrare din tabelul de alias-uri citează o înregistrare EUVD reală.

Raportarea unei vulnerabilități în euvd-watch însuși: [SECURITY.md](SECURITY.md) *(engleză)*.

## Licență

[EUPL-1.2](LICENSE). Documentație în engleză și română — versiunea de referință este
[README.md](README.md) (engleză).
