<p align="center">
  <img src="doc/assets/cyber-header.svg" alt="BitcoinAll Core — Banner ciberpunk 2026" width="100%"/>
</p>

<p align="center">
  <img src="doc/assets/btca-coin.svg" alt="Moneda BTCA" width="220"/>
</p>

<p align="center">
  <strong>Moneda descentralizada para todo el público</strong><br/>
  <a href="https://github.com/gonzalolinaresamezcua/BitcoinAll">github.com/gonzalolinaresamezcua/BitcoinAll</a> · <em>Proof of Uptime</em> · <em>Dev + AI</em> · 2026
</p>

<p align="center">
  <img src="https://img.shields.io/badge/consensus-Proof%20of%20Uptime-ff00aa?style=for-the-badge&labelColor=0a0014" alt="PoU"/>
  <img src="https://img.shields.io/badge/ticker-BTCA-00f5ff?style=for-the-badge&labelColor=0a0014" alt="BTCA"/>
  <img src="https://img.shields.io/badge/license-MIT-ffe600?style=for-the-badge&labelColor=0a0014" alt="MIT"/>
  <img src="https://img.shields.io/badge/era-cyberpunk%202026-7b2fff?style=for-the-badge&labelColor=0a0014" alt="2026"/>
</p>

---

<table>
<tr>
<td width="33%" align="center">
<img src="doc/assets/cyber-robot.svg" alt="Robot PoU" width="100%"/>
<br/><sub><b>PoW desactivado.</b> Aquí premiamos uptime, no GPUs fundidas.</sub>
</td>
<td width="33%" align="center">
<img src="doc/assets/cyber-network.svg" alt="Red P2P" width="100%"/>
<br/><sub>Nodos conectados. Sin bancos. Sin intermediarios.</sub>
</td>
<td width="33%" align="center">
<img src="doc/assets/cyber-skull-clock.svg" alt="Skull clock" width="120"/>
<br/><sub>Tiempo online = recompensa. <code>BTCA_TIME</code> en acción.</sub>
</td>
</tr>
</table>

<p align="center">
  <img src="doc/assets/cyber-hacker-cat.svg" alt="Gato hacker node kitten" width="240"/>
</p>

> **Repositorio oficial:** [github.com/gonzalolinaresamezcua/BitcoinAll](https://github.com/gonzalolinaresamezcua/BitcoinAll)  
> **Instalación:** compila desde el código ([doc/build-unix.md](doc/build-unix.md)) o revisa [Releases](https://github.com/gonzalolinaresamezcua/BitcoinAll/releases).  
> *El gato no mina. El gato permanece conectado. El gato gana.*

---

## Descarga e instalación

BitcoinAll **no tiene web de descarga propia**. El único sitio oficial del proyecto es este repositorio en GitHub.

| Opción | Enlace |
|--------|--------|
| **Compilar en Linux** | [doc/build-unix.md](doc/build-unix.md) |
| **Releases (binarios)** | [github.com/gonzalolinaresamezcua/BitcoinAll/releases](https://github.com/gonzalolinaresamezcua/BitcoinAll/releases) |
| **Issues y soporte** | [github.com/gonzalolinaresamezcua/BitcoinAll/issues](https://github.com/gonzalolinaresamezcua/BitcoinAll/issues) |

No uses enlaces tipo `@bitcoinall/en/download/` ni dominios de terceros: no pertenecen a este proyecto.

## ¿Qué es BitcoinAll Core?

BitcoinAll Core se conecta a la red peer-to-peer de BitcoinAll para descargar y validar completamente bloques y transacciones. Incluye wallet e interfaz gráfica (compilación opcional).

```mermaid
flowchart LR
    A[🖥️ Nodo BTCA] -->|P2P| B[🌐 Red]
    B --> C[⏱️ Uptime acumulado]
    C --> D[💰 Recompensa PoU]
    D --> E[📦 Bloque validado]
    style A fill:#0a0014,stroke:#00f5ff,color:#00f5ff
    style B fill:#12002b,stroke:#ff00aa,color:#ff00aa
    style C fill:#0a0014,stroke:#ffe600,color:#ffe600
    style D fill:#12002b,stroke:#7b2fff,color:#7b2fff
    style E fill:#0a0014,stroke:#00f5ff,color:#00f5ff
```

---

## Consenso · Proof of Uptime (PoU)

BitcoinAll usa **Proof of Uptime (PoU)**. En lugar de minería proof-of-work, la participación y las recompensas de bloque están ligadas al **tiempo de conexión acumulado** del nodo en la red.

| Concepto | Detalle |
|----------|---------|
| **Ticker** | `BTCA` |
| **Mecanismo** | Uptime de nodo, no hashrate |
| **TX especial** | `BTCA_TIME` — marca tiempo online |
| **PoW** | Desactivado (RIP ASICs, 2009–2026 💀) |
| **Parámetros** | `src/consensus/params.h` |

<p align="center">
  <img src="doc/assets/btca-coin.svg" alt="BTCA coin detail" width="140"/>
</p>

Más información en la [carpeta doc](/doc).

---

## Licencia

BitcoinAll Core se distribuye bajo la licencia **MIT**.

Copyright (c) 2025-2026 Bitcoin All Developers. Ver [COPYING](COPYING) o https://opensource.org/licenses/MIT.

---

## Proceso de desarrollo

La rama `master` se compila y prueba regularmente (ver `doc/build-*.md`), pero no está garantizada como completamente estable. Las [releases](https://github.com/gonzalolinaresamezcua/BitcoinAll/releases) marcan versiones estables.

Repositorio oficial: https://github.com/gonzalolinaresamezcua/BitcoinAll

Flujo de contribución: [CONTRIBUTING.md](CONTRIBUTING.md) · Notas para devs: [doc/developer-notes.md](doc/developer-notes.md).

---

## Testing

El cuello de botella del desarrollo es la revisión y las pruebas. Sé paciente y ayuda probando PRs de otros — esto es software crítico para seguridad financiera.

### Tests automatizados

- **Unit tests:** [src/test/README.md](src/test/README.md) — ejecutar con `ctest`
- **Funcionales / integración:** [test/](/test) — `build/test/functional/test_runner.py`
- **CI:** compila en Windows, Linux y macOS en cada PR

### QA manual

Cambios grandes o de alto riesgo deben probarse por alguien distinto al autor. Incluye un plan de pruebas en la descripción del PR si no es trivial.

---

## Traducciones

Las traducciones se gestionan en el repositorio. Abre un issue o pull request en [GitHub](https://github.com/gonzalolinaresamezcua/BitcoinAll) si quieres colaborar.

---

<p align="center">
  <img src="doc/assets/cyber-network.svg" alt="Red descentralizada" width="360"/>
</p>

<p align="center">
  <sub>
    <code>// BITCOINALL :: BTCA :: UPTIME &gt; HASHRATE :: 2026 //</code><br/>
    Hecho con neón, café y nodos que no se desconectan.
  </sub>
</p>
