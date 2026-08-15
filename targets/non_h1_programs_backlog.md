# Backlog de programas no-HackerOne (fuente: lista pasada por el usuario, 2026-08-15)

Lista cruda de programas de bug bounty fuera de HackerOne para
considerar como fuente de targets futuros, además de Immunefi (ya en
uso, ver `select_targets.py` y el batch fuzzeado esta sesión: tofn,
serai-dkg-pedpop, wsts, bellperson, rust-fil-proofs/fr32, neptune).
Sin investigar en profundidad todavía -- esto es un backlog, no una
selección. Nota de encaje con FRACTURE agregada donde es obvia a
simple vista (FRACTURE clona y fuzzea localmente, así que el filtro
real es: ¿hay componente open-source real, memory-unsafe, no cubierto
ya por OSS-Fuzz? -- la mayoría de estos programas grandes son
mayormente closed-source o ya están masivamente cubiertos).

## Programas grandes de vendors (mayormente closed-source o ya en OSS-Fuzz)

- **Google VRP** -- bughunters.google.com. Recompensas $100-$31,337+.
  Nota: los componentes open-source grandes de Google (Chromium, y
  por extensión V8/BoringSSL) están entre los proyectos MÁS
  fuzzeados del planeta por el propio OSS-Fuzz (que Google financia y
  opera) -- exactamente el tipo de duplicación de esfuerzo que
  `select_targets.py` está pensado para evitar. Podría valer la pena
  mirar proyectos MÁS chicos/nuevos de Google que todavía no estén en
  OSS-Fuzz, no los headliners.
- **Apple Security Bounty** -- developer.apple.com/security-bounty.
  Hasta $1,000,000. iOS/macOS/iCloud/Safari son mayormente
  closed-source -- no encaja con el modelo de FRACTURE (clonar y
  compilar localmente). Descartar salvo que aparezca un componente
  open-source específico (ej. WebKit, que a su vez también está en
  OSS-Fuzz).
- **Microsoft MSRC** -- msrc.microsoft.com. Hasta $250,000. Mismo
  problema: Windows/Azure/Office son closed-source. .NET/PowerShell
  sí son open-source y podrían valer una mirada puntual.
- **Meta Bug Bounty** -- facebook.com/whitehat. $500-$100,000+.
  Facebook/Instagram/WhatsApp son closed-source (servicios web), pero
  Meta tiene librerías open-source reales con historial de CVEs de
  memoria (ej. `folly`, `RocksDB`, `Buck2`) que sí podrían encajar si
  están en scope del programa -- falta confirmar.
- **GitHub Security Bug Bounty** -- bounty.github.com. $500-$30,000.
  Mayormente infraestructura web, no hay mucho C/C++/Rust propio
  fuzzeable localmente.
- **Shopify Bug Bounty** -- shopify.engineering/security-bug-bounty.
  Hasta $50,000. Web/Ruby, bajo encaje con el modelo de FRACTURE.
- **Tesla Product Security** -- tesla.com/security. Hasta $15,000.
  Vehículos/APIs -- fuera del modelo de FRACTURE (no hay forma de
  "clonar y compilar" un vehículo).
- **Intel Bug Bounty** -- intel.com (bug-bounty-program). Hasta
  $100,000. Firmware/drivers -- interesante en teoría (memory-unsafe
  real, C), pero closed-source en su mayoría.
- **Mozilla Security Bug Bounty** -- mozilla.org/security/bug-bounty.
  Hasta $10,000. Firefox es open-source real (C++/Rust) pero, igual
  que Chromium, está fuertemente cubierto por el propio fuzzing
  continuo de Mozilla (parte de OSS-Fuzz también) -- mismo problema de
  duplicación que Google VRP.
- **Oracle VRP** -- oracle.com (vulnerability-reporting). Hasta
  $30,000. Mayormente closed-source.

## Web3 independientes (buen encaje potencial, sin evaluar todavía)

- **HackenProof** -- hackenproof.com. Recompensas en cripto,
  independiente de H1/Bugcrowd. Mismo perfil que Immunefi (proyectos
  blockchain/cripto, probable buena densidad de Rust/Go/C++) -- buen
  candidato para el mismo tipo de cruce que se hizo con el mirror de
  Immunefi, falta confirmar si tiene un feed público/API similar.
- **Code4rena** -- code4rena.com. Auditorías competitivas -- distinto
  formato (concursos con ventana de tiempo fija, no bounty continuo),
  pero mismo perfil de código (smart contracts + a veces
  infraestructura Rust/Go de protocolos).
- **Sherlock** -- sherlock.xyz. Auditorías + bounties, mismo perfil
  que Code4rena.
- **Fortress** -- fortress.build. Auditorías y bug bounties, sin
  evaluar.

## Programas independientes de empresas chicas (sin catalogar)

Miles de programas VRP propios sin plataforma externa, descubribles
por convención (`/.well-known/security.txt`, `/security`,
`/bug-bounty`, `/vulnerability-disclosure`) -- no hay una lista
centralizada como la de Immunefi, requeriría descubrimiento caso por
caso. No es una fuente práctica para un batch como el que se hizo esta
sesión; mejor dejarlo para cuando aparezca un proyecto open-source
puntual que valga la pena (ej. por historial de CVEs de memoria) y
recién ahí chequear si tiene su propio programa.

## Próximo paso sugerido (no ejecutado todavía)

De toda la lista, lo más accionable para el mismo patrón que ya
funcionó con Immunefi es **HackenProof** -- mismo perfil
cripto/blockchain, mayor probabilidad de proyectos Rust/Go/C++ chicos
sin cobertura de OSS-Fuzz. Evaluar si tiene un endpoint público
listable (como el mirror de GitHub que se usó para Immunefi) antes de
invertir tiempo en scrapear a mano.
