# Glosar — fiecare termen tehnic, pe înțelesul tuturor

Fiecare intrare: ce înseamnă termenul și ce înseamnă el **în interiorul euvd-watch**. Ordonat pe teme, ca termenii înrudiți să stea împreună. Dacă întâlnești în documentație un termen care lipsește de aici, e un bug de documentație — te rugăm să deschizi un issue.

> Versiunea în limba engleză: [GLOSSARY.md](GLOSSARY.md). Terminologia tehnică din ecosistem (SBOM, purl, finding, hash-chained) este păstrată în engleză, pentru că așa apare în tool-uri și în documentele oficiale — explicațiile sunt în română.

---

## 1. Inventare de software

**SBOM (Software Bill of Materials — lista de materiale software)**
O listă citibilă de mașini cu fiecare componentă software („ingredient") din interiorul unui program: nume, versiuni și identificatori. Exact ca lista de ingrediente de pe un ambalaj alimentar, dar pentru software.
*În euvd-watch:* intrarea pentru absolut tot. Tu aduci un SBOM (generat de un tool precum Syft); euvd-watch îl citește.

**CycloneDX**
Unul dintre cele două formate majore de SBOM, întreținut de OWASP. De obicei un fișier JSON.
*În euvd-watch:* format de intrare acceptat (versiunile 1.4–1.6, JSON).

**SPDX**
Celălalt format major de SBOM, întreținut de Linux Foundation și standardizat ca ISO/IEC 5962.
*În euvd-watch:* format de intrare acceptat (2.3, JSON) — de exemplu exportul SBOM integrat în GitHub.

**Componentă**
O intrare dintr-un SBOM: o bibliotecă, o aplicație, un pachet de sistem de operare sau o imagine de container, cu versiunea și identificatorii ei.
*În euvd-watch:* modelul intern normalizat pe care operează tot restul, indiferent din ce format de SBOM a venit.

**PURL (Package URL)**
Un identificator compact și standardizat pentru un pachet software, de exemplu `pkg:pypi/pillow@10.1.0` — codifică ecosistemul (pypi), numele (pillow) și versiunea. Precis și fără ambiguități.
*În euvd-watch:* identificatorul de componentă preferat din SBOM-uri. Atenție: înregistrările EUVD **nu** folosesc purl-uri — exact de aceea e nevoie de un motor de matching.

**CPE (Common Platform Enumeration)**
Un identificator mai vechi, în stil NVD, pentru produse software, de forma `cpe:2.3:a:vendor:produs:versiune:...`. Foarte răspândit în bazele de date de vulnerabilități, dar mai dezordonat decât purl (numele de vendor/produs sunt inconsecvente).
*În euvd-watch:* cea mai bună punte între componentele din SBOM și înregistrările de vulnerabilități, atunci când SBOM-ul îl include.

**Syft / cdxgen**
Tool-uri open-source populare care *generează* SBOM-uri inspectându-ți codul, containerele sau sistemul de fișiere.
*În euvd-watch:* însoțitori recomandați. euvd-watch **nu** generează SBOM-uri, în mod deliberat — consumă ce produc aceste tool-uri.

---

## 2. Vulnerabilități, baze de date și scoruri

**Vulnerabilitate**
Un defect din software pe care un atacator l-ar putea exploata — „ingredientul stricat".

**CVE (Common Vulnerabilities and Exposures)**
Sistemul global de denumire a vulnerabilităților. Fiecare primește un ID de forma `CVE-2026-12345`, ca toată lumea să vorbească despre același defect.
*În euvd-watch:* înregistrările EUVD poartă ID-uri CVE ca alias-uri; euvd-watch le folosește pentru a face legătura cu EPSS și KEV.

**EUVD (European Union Vulnerability Database)**
Baza de date de vulnerabilități proprie a Europei, operată de ENISA, creată în baza directivei NIS2. Înregistrările au ID-uri proprii, alias-uri CVE, date despre produsele afectate și — esențial — un marcaj pentru vulnerabilitățile **exploatate activ**.
*În euvd-watch:* sursa principală de date. Proiectul există pentru că nu se construise nimic open în jurul EUVD.

**ENISA**
Agenția Uniunii Europene pentru Securitate Cibernetică — organismul UE care operează EUVD și care primește notificările CRA (împreună cu CSIRT-urile naționale).

**NVD (National Vulnerability Database)**
Baza de date guvernamentală americană, veche și consacrată. Majoritatea scanerelor existente sunt construite în jurul ei.
*În euvd-watch:* nefolosită direct — euvd-watch este deliberat EUVD-first, reducând dependența de o singură sursă din afara UE.

**OSV (Open Source Vulnerabilities)**
O bază de date deschisă inițiată de Google, axată pe vulnerabilitățile pachetelor open-source, cu o precizie foarte bună pe ecosistem și versiune.
*În euvd-watch:* sursă suplimentară potențială; nu principală.

**CISA KEV (Known Exploited Vulnerabilities)**
Un catalog întreținut de agenția americană de securitate cibernetică (CISA), care listează **doar** vulnerabilitățile confirmate ca fiind exploatate în sălbăticie. Mic, dar cu semnal foarte bun.
*În euvd-watch:* sursă de îmbogățire și una dintre condițiile configurabile de declanșare CRA.

**„Exploatat activ" (actively exploited)**
O vulnerabilitate pe care atacatorii o folosesc *chiar acum*, în atacuri reale — nu doar un defect teoretic. Diferența dintre „modelul ăsta de yală se poate sparge" și „hoții de pe strada ta sparg yala asta la noapte".
*În euvd-watch:* semnalul cu cea mai mare prioritate și condiția care pornește obligațiile de raportare CRA.

**EPSS (Exploit Prediction Scoring System)**
Un scor de probabilitate (0–1), actualizat zilnic, care estimează cât de probabil este ca o vulnerabilitate să fie exploatată în următoarele 30 de zile. Produs de FIRST.org.
*În euvd-watch:* îmbogățire pe fiecare finding și condiție opțională de declanșare CRA (`epss >= prag`).

**CVSS (Common Vulnerability Scoring System)**
Clasicul scor de *severitate* de la 0 la 10 al unei vulnerabilități. Măsoară cât de rău *ar fi* dacă ar fi exploatată — nu cât de probabilă e exploatarea (aia e EPSS).
*În euvd-watch:* afișat pentru context; implicit nu declanșează nimic.

**Finding**
Termenul propriu al euvd-watch: o pereche (componentă, înregistrare de vulnerabilitate) despre care motorul de matching crede că sunt legate, cu un nivel de încredere și o explicație pe înțelesul oamenilor a *motivului*.

**Scor de încredere (high / medium / low)**
Eticheta de onestitate pe care euvd-watch o pune pe fiecare finding. `high` = identificatori structurați și versiune demonstrabil în intervalul afectat; `medium` = dovezi bune, dar incomplete; `low` = un indiciu de similaritate de nume, care există doar pentru verificare umană. Deciziile automate nu se construiesc niciodată pe `low`.

**Fals pozitiv**
O alertă despre o problemă care de fapt nu te privește (de exemplu, funcția vulnerabilă există în bibliotecă, dar doar într-o versiune pe care n-o folosești). Motivul numărul unu pentru care tool-urile de securitate ajung să fie ignorate.
*În euvd-watch:* inamicul împotriva căruia există declarațiile VEX (mai jos).

---

## 3. Decizii și documente

**VEX (Vulnerability Exploitability eXchange)**
O declarație citibilă de mașini care răspunde la întrebarea: „vulnerabilitatea X a fost raportată pentru produsul tău — chiar îl *afectează*?" Răspunsuri posibile: afectat / neafectat / reparat / în investigare. VEX este modul în care reduci la tăcere falsele pozitive *cu un motiv documentat*, în loc să ignori pur și simplu alertele.

**OpenVEX**
O specificație deschisă și minimală pentru scrierea documentelor VEX (există formate concurente; OpenVEX este cel mai simplu și cel mai prietenos cu tool-urile).
*În euvd-watch:* formatul de ieșire al comenzii `vex generate`. Scanerele din aval îl pot consuma și nu mai alertează pentru non-probleme documentate.

**Justificare (justification)**
Într-o declarație VEX `not_affected`, *motivul* standardizat și citibil de mașini (de exemplu `vulnerable_code_not_present`). OpenVEX îl cere obligatoriu — nu poți spune doar „nu ne afectează, aveți încredere".
*În euvd-watch:* obligatorie, plus o explicație în limbaj natural deasupra.

**VEX conservator**
Regula de design a euvd-watch: tool-ul scrie automat `not_affected` **doar** când poate demonstra asta mecanic (de exemplu, versiunea ta este demonstrabil în afara intervalului afectat, cu încredere ridicată). Tot ce e incert rămâne `under_investigation`, pentru un om. Tool-ul nu are voie să ascundă un risc real ca să pară ordonat.

**Fișierul de decizii (`vex-decisions.yaml`)**
Partea umană a buclei: un fișier YAML în care o persoană consemnează judecăți („noi nu livrăm acea ramură de cod"), pe care euvd-watch le îmbină cu propriile ciorne automate. Deciziile umane câștigă întotdeauna — explicit și la vedere.

---

## 4. Legislație europeană

**CRA (Cyber Resilience Act — Regulamentul privind reziliența cibernetică)**
Regulamentul UE care impune obligații de securitate cibernetică producătorilor de „produse cu elemente digitale" (adică aproape orice software și hardware conectat vândut în UE) — dezvoltare securizată, tratarea vulnerabilităților și raportarea incidentelor și a vulnerabilităților.
*În euvd-watch:* motivul de reglementare pentru care există fluxul M4.

**Articolul 14 (din CRA)**
Articolul care obligă producătorii să notifice autoritățile despre **vulnerabilitățile exploatate activ** din produsele lor, cu termene stricte: o avertizare timpurie în **24 de ore** de la momentul luării la cunoștință, o notificare mai completă în **72 de ore** și un raport final mai târziu. (euvd-watch tratează stagiile exacte ca fiind configurabile și le verifică față de textul legal în vigoare.)
*În euvd-watch:* fluxul trigger → ceas → ciornă → audit al etapei M4.

**Avertizare timpurie (early warning)**
Prima notificare CRA, minimală — „am luat la cunoștință o vulnerabilitate exploatată activ" — datorată în 24 de ore de la momentul luării la cunoștință.
*În euvd-watch:* documentul pe care `cra draft` îl precompletează. Un om îl verifică și îl transmite întotdeauna; tool-ul nu depune niciodată nimic de unul singur.

**CSIRT (Computer Security Incident Response Team)**
Echipa națională de răspuns la incidente de securitate cibernetică. Notificările CRA merg către CSIRT-ul desemnat și către ENISA, prin canalele oficiale.

**NIS2**
Directiva UE privind securitatea cibernetică a entităților critice și importante. Relevantă aici pentru că a impus crearea EUVD și pentru că organizațiile reglementate NIS2 sunt utilizatori naturali ai acestui tool.

**Producător (manufacturer)**
În limbajul CRA: oricine dezvoltă sau vinde în UE un produs cu elemente digitale — inclusiv mulți furnizori de software care nu se consideră „producători".

---

## 5. Termeni de inginerie folosiți în acest proiect

**CI/CD (integrare continuă / livrare continuă)**
Pipeline-urile automate care construiesc și testează software-ul la fiecare modificare (de exemplu GitHub Actions, GitLab CI).
*În euvd-watch:* și locul unde e testat euvd-watch însuși, și locul unde îl rulează utilizatorii (prin action-ul/template-ul furnizate) ca să blocheze build-urile pe finding-uri noi.

**Cod de ieșire (exit code)**
Numărul pe care o comandă îl returnează apelantului. Convenția de aici: `0` = curat, `1` = finding-uri peste politica ta, `2` = eroare de execuție. Așa „citește" un pipeline de CI verdictul euvd-watch.

**Cache / TTL (Time To Live)**
Stocarea locală a răspunsurilor API (cache) și cât timp rămân valabile (TTL). Protejează API-ul beta al ENISA de a fi bombardat și permite euvd-watch să funcționeze în timpul unei indisponibilități — cu un avertisment explicit despre prospețimea datelor.

**Modul watch**
Rularea matching-ului după un program, pe un SBOM *stocat*, pentru că vulnerabilități noi apar mult după ce ai livrat. Sunt raportate doar finding-urile *noi sau schimbate*.

**Jurnal de audit (audit log)**
Un jurnal append-only cu tot ce s-a întâmplat: trigger-e declanșate, ceasuri pornite, ciorne generate, confirmări umane.

**Tamper-evident / lanț de hash-uri (hash chain)**
Fiecare intrare din jurnalul de audit include hash-ul criptografic al intrării precedente, formând un lanț. Nu poți modifica sau șterge pe ascuns o pagină fără să se rupă toate hash-urile ulterioare — `cra verify-log` detectează exact punctul rupt. Nu *împiedică* falsificarea (nimic local nu poate); o face **detectabilă**.

**Human-in-the-loop (omul în buclă)**
Regula de design conform căreia automatizarea redactează, iar omul decide. În euvd-watch nimic nu este transmis, depus sau suprimat fără ca o persoană să confirme.

**Ieșire deterministă**
Aceleași intrări produc întotdeauna ieșiri identice octet cu octet (ordonare stabilă, fără elemente aleatorii). Contează pentru audituri reproductibile și pentru diff-uri de încredere în git și în CI.

**Self-hostable (găzduit la tine)**
Poți rula totul — pipeline și dashboard — pe propria infrastructură. Fără dependență de SaaS; SBOM-urile și finding-urile tale nu îți părăsesc niciodată sistemele.

**WCAG (Web Content Accessibility Guidelines)**
Standardul care face interfețele web utilizabile de către persoanele cu dizabilități (navigare de la tastatură, cititoare de ecran, contrast). Nivelul AA este ținta obișnuită de conformitate.
*În euvd-watch:* un angajament explicit pentru dashboard-ul M6.

**EUPL (European Union Public Licence)**
O licență open-source creată de Comisia Europeană, compatibilă cu principalele licențe copyleft.
*În euvd-watch:* licența proiectului (EUPL-1.2) — o alegere deliberat europeană pentru un tool deliberat european.

**Grype / Trivy**
Scanere de vulnerabilități open-source populare, construite în principal în jurul datelor NVD/OSV.
*În euvd-watch:* complementare, nu concurente — ele acoperă bazele de date centrate pe SUA; euvd-watch acoperă EUVD și fluxul CRA, iar ieșirea lui VEX le poate reduce falsele pozitive.
