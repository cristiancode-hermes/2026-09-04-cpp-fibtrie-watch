# Arquitectura — fibtrie-watch

## Flujo

```
/proc/net/fib_trie      ──► parse_trie_tree_file() ──► Snapshot.leaves[]
/proc/net/fib_triestat  ──► parse_triestat_file()   ──► Snapshot.stats[]
                                                           │
        ┌──────────────────────────────────────────────────┤
        ▼            ▼              ▼              ▼
 render_stats()  render_counters() render_leaves()  render_json()
 (tabla por      (gets/matches/    (prefijos no-   (tables[] +
  tabla + hist)   null_hit)         LOCAL)          leaves[])
```

## Estructura de datos

- `FibLeaf` — dirección + `/len`, tipo (`LOCAL`/`UNICAST`/`BROADCAST`), la fila
  de info completa (`/32 host LOCAL`) y profundidad en el árbol.
- `TrieStats` — una entrada por tabla (`Main`/`Local`): profundidad media (×100),
  máxima, leaves, prefixes, internos, punteros, null ptrs, tamaño KB, contadores
  de lookups e histograma por profundidad.
- `Snapshot` — `leaves[]` + `stats[]` fusionados por nombre de tabla
  (`stat_of(table)`).

## Parsing

- **Árbol** (`fib_trie_show`): filas `+-- x/y` = nodos internos (solo ancla);
  filas `|-- addr` = hojas; filas `+-- addr` (sin `/`) = hojas standalone de
  Local. La línea de info siguiente (`/32 host LOCAL`) se adjunta a la dirección
  pendiente (`pending_addr`). Los markers `+--`/`|--` se buscan en la línea RAW
  (la vista recortada pierde la indentación).
- **Stats** (`fib_triestat_seq_show`): claves con `:` (`Leaves: 7`) y contadores
  con `= ` (`gets = 5862015`, `null node hit= 886411`). El histograma
  `1: 1  2: 3  3: 1` son pares `profundidad:conteo` — se ignoran los tokens de
  conteo.
- Comentarios `#` y líneas basura se toleran en `--file`.

## Decisiones

- **C++23 stdlib-only**: g++ directo, cero dependencias.
- **Doble fuente**: el árbol solo no da profundidades/contadores; el triestat
  solo no da las direcciones. Fusionar por tabla da el cuadro completo.
- **`--demo`**: dos tablas con 6+7 leaves, un BROADCAST, `+-- 172.16.1.2` (hoja
  standalone) y contadores fijos clonados del triestat real del host.
- **`gets` monotónico**: se verifica en el selftest con dos lecturas separadas
  300 ms — un único parseo no puede comprobarlo.