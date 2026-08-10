# CONFIRMADO: nil pointer dereference / index out of range real en extractConfig() (fabric-sdk-go), reachable desde una respuesta de peer u orderer

**Estado: bug real y 100% determinístico, confirmado con un repro
directo (no hizo falta fuzzing -- se vio leyendo el código y se
confirmó con dos tests mínimos). NO reportado todavía.**

## Por qué este target

Mientras corría una campaña larga de fuzzing sobre `fabric-gateway`
(`FuzzParseTransactionEnvelope`, ver más abajo, sin crashes hasta el
momento de escribir esto), revisé en paralelo `fabric-sdk-go` -- el
SDK cliente "clásico" de Fabric (predecesor de fabric-gateway, todavía
ampliamente usado en producción), otro de los candidatos reales de
`targets/select_targets.py` sin tocar todavía.

## Candidato real confirmado

`pkg/fab/chconfig/chconfig.go:367`:

```go
func extractConfig(channelID string, block *common.Block) (*ChannelCfg, error) {
	if block.Header == nil {
		return nil, errors.New("expected header in block")
	}

	configEnvelope, err := resource.CreateConfigEnvelope(block.Data.Data[0])  // <- linea 372
	...
```

Chequea `block.Header == nil`, pero **no chequea `block.Data == nil`
ni que `block.Data.Data` tenga al menos un elemento** antes de indexar
`block.Data.Data[0]`.

`common.Block` (generado por protobuf, `fabric-protos-go/common`):

```go
type Block struct {
	Header   *BlockHeader   // opcional, proto3
	Data     *BlockData     // opcional, proto3 -- puede venir nil perfectamente
	Metadata *BlockMetadata
}
type BlockData struct {
	Data [][]byte  // puede venir vacio perfectamente
}
```

Como es proto3, un mensaje `Block` con `Header` seteado pero `Data`
ausente (nil) es **perfectamente válido** a nivel de
`proto.Unmarshal` -- no hay forma de distinguirlo de un mensaje
truncado o de una respuesta legítima con un campo opcional vacío
sin este chequeo explícito, que no existe.

## Reachability real (sin intermediarios que ya validen esto)

```go
func (c *ChannelConfig) queryBlockFromPeers(reqCtx reqContext.Context) (*common.Block, error) {
	...
	block, err := retry.NewInvoker(retryHandler).Invoke(func() (interface{}, error) {
		return l.QueryConfigBlock(reqCtx, targets, &channel.TransactionProposalResponseVerifier{...})
	})
	...
	return block.(*common.Block), nil
}

func (c *ChannelConfig) queryPeers(reqCtx reqContext.Context) (*ChannelCfg, error) {
	block, err := c.queryBlockFromPeers(reqCtx)
	...
	return extractConfig(c.channelID, block)   // directo, sin validar Data en el medio
}
```

Y el mismo patrón para `queryBlockFromOrderer` / `queryOrderer`
(chconfig.go:238-247), que llama a `resource.LastConfigFromOrderer`
y pasa el resultado directo a `extractConfig` también sin validar.

Ambos caminos cuelgan del método público
`ChannelConfig.Query(reqCtx)` (chconfig.go:151), que es exactamente
la función que una aplicación real usa para consultar la
configuración de canal -- ya sea contra peers o contra el orderer,
según config. El `*common.Block` que llega ahí es la respuesta real
de un peer o un orderer de la red -- un participante ya autenticado
del canal (no un atacante anónimo de internet), pero **el modelo de
red de Fabric explícitamente tolera participantes bizantinos/con
bugs propios sin que el resto del sistema deba caerse por eso** -- un
solo peer u orderer devolviendo un bloque de config incompleto (por
bug propio, no necesariamente malicia) tira abajo a CUALQUIER cliente
que lo consulte.

## Confirmación empírica (repro directo, determinístico)

```go
func TestFractureReproNilBlockData(t *testing.T) {
	block := &common.Block{
		Header: &common.BlockHeader{Number: 1},
		// Data intencionalmente nil
	}
	_, _ = extractConfig("mychannel", block)
}
```

```
panic: runtime error: invalid memory address or nil pointer dereference [recovered]
	panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x8 pc=0x9e04ea]
...
github.com/hyperledger/fabric-sdk-go/pkg/fab/chconfig.extractConfig(...)
	.../pkg/fab/chconfig/chconfig.go:372 +0x2a
```

Segunda variante, `Data` no nil pero vacío:

```go
func TestFractureReproEmptyBlockData(t *testing.T) {
	block := &common.Block{
		Header: &common.BlockHeader{Number: 1},
		Data:   &common.BlockData{Data: [][]byte{}},
	}
	_, _ = extractConfig("mychannel", block)
}
```

```
panic: runtime error: index out of range [0] with length 0 [recovered]
	panic: runtime error: index out of range [0] with length 0
...
github.com/hyperledger/fabric-sdk-go/pkg/fab/chconfig.extractConfig(...)
	.../pkg/fab/chconfig/chconfig.go:372 +0x2e7
```

Ambas variantes crashean de forma 100% determinística, en la misma
línea exacta, sin necesitar fuzzing -- se reproduce siempre.

## Impacto

- **Denial of Service del lado cliente**: cualquier aplicación que
  use `fabric-sdk-go` y llame `ChannelConfig.Query()` (consulta de
  configuración de canal, una operación estándar) contra un peer u
  orderer que devuelva un bloque de config con `Data` ausente o vacío
  crashea con un panic no recuperado -- termina el proceso de la
  aplicación cliente (Go no recupera panics automáticamente salvo que
  el código llamador tenga un `recover()` explícito alrededor de esta
  llamada, que no es el patrón típico).
- No requiere que el peer/orderer sea controlado por un atacante
  externo anónimo -- alcanza con que UN SOLO participante ya
  autenticado del canal tenga un bug propio, esté mal configurado, o
  esté comprometido, para tirar abajo a cualquier cliente que lo
  consulte. Encaja con el modelo de amenaza bizantino que blockchain
  en general dice tolerar.

## Severidad -- honesto

- Confirmado el crash, determinístico, con causa raíz exacta.
- No confirmado (no investigado en esta sesión): si existe algún
  camino donde un peer/orderer *legítimo y no buggy* podría devolver
  esto en la práctica (ej. un canal recién creado sin bloques de
  config todavía, algún estado transitorio real) -- si existiera,
  esto podría ser más un bug de robustez alcanzable en operación
  normal que solo por un participante bizantino, lo cual subiría la
  severidad real. Vale la pena investigar antes de reportar.

## Próximo paso

1. Investigar si hay algún escenario de operación normal (no
   bizantino) donde `block.Data` podría llegar nil/vacío -- afecta la
   clasificación de severidad real antes de reportar.
2. Si se confirma que solo un participante bizantino/buggy puede
   disparar esto: sigue siendo reportable (el programa de bug bounty
   real de Hyperledger/LFDT en HackerOne -- confirmado en esta sesión,
   ver `2026-08-10_fabric-private-chaincode_parson_REPORT_DRAFT_EN.md`
   -- tiene `fabric-sdk-go` en el alcance elegible), clasificable
   como Medium/High según como lo interprete el equipo de seguridad.
3. Buscar el mismo patrón (`.Data.Data[0]` u otro acceso a índice fijo
   sin chequeo de longitud) en otros lugares del mismo archivo/paquete
   -- `loadConfig`/`loadConfigValue` tienen varios `proto.Unmarshal`
   más que no se auditaron todavía uno por uno.
