# protobuf_experiment/

Código real del experimento #7 (ver `../README.md`) -- reimplementación
en Go del álgebra de operadores (`transpose`/`semantic_inverse`/
`interleave`) operando sobre `*cb.ConfigGroup`/`*cb.ConfigUpdate` reales
(protobuf, `hyperledger/fabric-protos-go-apiv2`), en vez de `dict`/
`list` de Python -- necesario porque `NewEnvelope` (target real
`fabric_config_newenvelope`) deserializa protobuf, no JSON.

## Uso

```
GOTOOLCHAIN=go1.25.10 go build -o gen_mutants .
./gen_mutants <rng-seed> <dir-baseline> <dir-treatment>
```

Genera 4 seeds reales (árboles `ConfigGroup` de 2-4 niveles) en ambos
directorios, más 200 mutantes en `dir-treatment`, en el formato real
del corpus nativo de Go (`go test fuzz v1\n[]byte(%q)`) -- listo para
copiar a `testdata/fuzz/FuzzNewEnvelope/` de un clon real de
`hyperledger/fabric-config` y correr `go test -fuzz=FuzzNewEnvelope`.

## Resultado real (ver `../README.md`, experimento #7)

Primer resultado negativo y consistente de toda la serie: -2.70% de
cobertura real, tratamiento pierde 5/5 repeticiones. Reveló un límite
real de la técnica -- protobuf es un formato binario denso donde la
mayoría de las mutaciones de bytes producen wire-format inválido (que
ejercita rutas de error reales del unmarshaler), un espacio que un
mutador que solo opera en el árbol ya deserializado nunca visita.
