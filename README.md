# fibtrie-watch

Inspector del **Patricia trie IPv4** del kernel Linux en C++23, zero deps.

Lee dos fuentes complementarias de `/proc/net`:

- `/proc/net/fib_trie` — el árbol en sí: tablas `Main` y `Local`, nodos internos
  (`+-- prefijo/longitud`) y hojas (`|-- dirección` + línea `/len scope TYPE`).
- `/proc/net/fib_triestat` — las estadísticas por tabla: profundidad media/máxima,
  leaves, prefixes, nodos internos, punteros, histograma por profundidad y los
  contadores de lookups (`gets`, `semantic match`, `null node hit`, `backtracks`).

## Features

- **Doble fuente**: árbol + stats, fusionadas por tabla (`Main` / `Local`)
- **Vista por defecto**: resumen por tabla (depth, avg, leaves, prefixes, ptrs,
  histograma `1:1 2:3 3:1`) + primeras 12 hojas no-LOCAL
- **Hojas**: prefijo, tipo (`LOCAL`/`UNICAST`/`BROADCAST`), profundidad en el trie
- **`--local`**: lista las direcciones `LOCAL` del host
- **`--counters`**: tabla de contadores de lookups (gets / matches / null_hit /
  backtracks)
- **`--tree`**: dump crudo de `/proc/net/fib_trie` con resaltado de sintaxis
  (LOCAL verde, BROADCAST amarillo, cabeceras bold)
- **Filtros**: `--top N`, `--leaves` (solo hojas), `--stats` (solo resumen)
- **Modo watch (`--watch N`)**: refresh periódico con flush por frame
- **Salida JSON (`--json`)**: `tables[]` + `leaves[]`, claves siempre citadas
- **Demo mode (`--demo`)**: host sintético dual-table (eth0 10.10.0.0/16,
  br0 172.16.1.0/24, docker 172.17.0.0/16, 192.168.0.0/24)
- **`--file`**: parsea un dump (formato árbol y/o triestat, tolera comentarios `#`)
- **`--no-color`**: paleta ANSI mutable (0 códigos en pipes)
- **Selftest**: 44 checks (demo, `/proc` real, monotonicidad de contadores,
  JSON parseable, --no-color, helpers)

## Build

```bash
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o fibtrie-watch
```

## Usage

```bash
# Snapshot único (host real)
./fibtrie-watch

# Demo (host sintético)
./fibtrie-watch --demo

# Solo resumen por tabla
./fibtrie-watch --stats

# Contadores de lookups
./fibtrie-watch --counters

# Hojas no-LOCAL
./fibtrie-watch --leaves

# Direcciones locales del host
./fibtrie-watch --local

# Dump crudo coloreado
./fibtrie-watch --tree

# Top 5 hojas
./fibtrie-watch --top 5

# Modo watch (cada 2s)
./fibtrie-watch --watch 2

# JSON
./fibtrie-watch --json

# Parsear un dump con comentarios
./fibtrie-watch --file sample-fibtrie.table --no-color

# Sin colores
./fibtrie-watch --no-color

# Auto-tests
./fibtrie-watch --selftest
```

## Data Sources

| Campo | Origen |
|-------|--------|
| árbol `Main`/`Local` | `/proc/net/fib_trie` (`fib_trie_show`) |
| profundidades, leaves, prefixes, ptrs, histograma | `/proc/net/fib_triestat` |
| contadores `gets`/`matches`/`null_hit` | `/proc/net/fib_triestat` (sección Counters) |
| tipos de hoja | línea de info `/len scope TYPE` del árbol |

## Notas

- Los nodos internos (`+-- x/y`) no son hojas: el catálogo de hojas sale de filas
  `|--` y de `+-- <addr>` sin longitud (leaves standalone de la tabla `Local`).
- `gets` es monotónico (contador acumulado de lookups); el selftest lo verifica
  leyendo dos veces con 300 ms de separación.
- El histograma del triestat (`1: 1  2: 3  3: 1`) son pares `profundidad: nº
  nodos` — el parser descarta la columna de conteo.