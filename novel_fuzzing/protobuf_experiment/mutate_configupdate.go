package main

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"google.golang.org/protobuf/proto"
)

// Operador transpose: intercambia dos entradas de Values o de Groups
// del mismo ConfigGroup (mismo criterio que op_transpose en
// novel_fuzzing/operator_tree.py -- nunca inventa un valor nuevo,
// solo reordena/cruza los que ya estan).
func collectGroups(root *cb.ConfigGroup, out *[]*cb.ConfigGroup) {
	if root == nil {
		return
	}
	*out = append(*out, root)
	for _, g := range root.Groups {
		collectGroups(g, out)
	}
}

func allGroups(u *cb.ConfigUpdate) []*cb.ConfigGroup {
	var out []*cb.ConfigGroup
	collectGroups(u.ReadSet, &out)
	collectGroups(u.WriteSet, &out)
	return out
}

func opTranspose(u *cb.ConfigUpdate, rng *rand.Rand) {
	groups := allGroups(u)
	if len(groups) == 0 {
		return
	}
	g := groups[rng.Intn(len(groups))]
	if len(g.Values) >= 2 {
		keys := make([]string, 0, len(g.Values))
		for k := range g.Values {
			keys = append(keys, k)
		}
		k1, k2 := keys[rng.Intn(len(keys))], keys[rng.Intn(len(keys))]
		if k1 != k2 {
			g.Values[k1], g.Values[k2] = g.Values[k2], g.Values[k1]
		}
	} else if len(g.Groups) >= 2 {
		keys := make([]string, 0, len(g.Groups))
		for k := range g.Groups {
			keys = append(keys, k)
		}
		k1, k2 := keys[rng.Intn(len(keys))], keys[rng.Intn(len(keys))]
		if k1 != k2 {
			g.Groups[k1], g.Groups[k2] = g.Groups[k2], g.Groups[k1]
		}
	}
}

// Operador semantic_inverse: invierte el significado logico de un
// campo escalar real -- ModPolicy vacio<->no-vacio, Value []byte
// vacio<->no-vacio -- mismo criterio que op_semantic_inverse.
func opSemanticInverse(u *cb.ConfigUpdate, rng *rand.Rand) {
	groups := allGroups(u)
	if len(groups) == 0 {
		return
	}
	g := groups[rng.Intn(len(groups))]
	if g.ModPolicy != "" {
		g.ModPolicy = ""
	} else {
		g.ModPolicy = "Admins"
	}
	for _, v := range g.Values {
		if len(v.Value) > 0 {
			v.Value = []byte{}
		} else {
			v.Value = []byte("x")
		}
		break
	}
}

// Operador interleave: mezcla los Groups de u con los de other --
// mismo criterio que op_interleave (solo mezcla contra los seeds
// ORIGINALES, nunca contra mutantes ya generados, evita el
// crecimiento compuesto ya documentado como bug real en
// seed_from_operator_tree.py).
func opInterleave(u *cb.ConfigUpdate, other *cb.ConfigUpdate, rng *rand.Rand) {
	if other.ReadSet != nil && u.ReadSet != nil {
		for k, v := range other.ReadSet.Groups {
			if u.ReadSet.Groups == nil {
				u.ReadSet.Groups = map[string]*cb.ConfigGroup{}
			}
			u.ReadSet.Groups[k] = proto.Clone(v).(*cb.ConfigGroup)
		}
	}
	if other.WriteSet != nil && u.WriteSet != nil {
		for k, v := range other.WriteSet.Groups {
			if u.WriteSet.Groups == nil {
				u.WriteSet.Groups = map[string]*cb.ConfigGroup{}
			}
			u.WriteSet.Groups[k] = proto.Clone(v).(*cb.ConfigGroup)
		}
	}
}

// mutate: evalua seq(loop(interleave,3), choice(transpose, semantic_inverse))
// -- misma expresion literal que el modulo de Python, traducida a Go
// porque la mutacion real necesita structs de protobuf reales, no
// dict/list de Python.
func mutate(u *cb.ConfigUpdate, seeds []*cb.ConfigUpdate, rng *rand.Rand) *cb.ConfigUpdate {
	result := proto.Clone(u).(*cb.ConfigUpdate)
	for i := 0; i < 3; i++ {
		other := seeds[rng.Intn(len(seeds))]
		opInterleave(result, other, rng)
	}
	if rng.Intn(2) == 0 {
		opTranspose(result, rng)
	} else {
		opSemanticInverse(result, rng)
	}
	return result
}

func buildSeeds() []*cb.ConfigUpdate {
	mkGroup := func(modPolicy string, values map[string][]byte, subgroups map[string]*cb.ConfigGroup) *cb.ConfigGroup {
		vals := map[string]*cb.ConfigValue{}
		for k, v := range values {
			vals[k] = &cb.ConfigValue{Version: 0, Value: v, ModPolicy: modPolicy}
		}
		return &cb.ConfigGroup{Version: 0, Groups: subgroups, Values: vals, ModPolicy: modPolicy}
	}

	// Seed 1: arbol chico, 3 niveles reales.
	s1 := &cb.ConfigUpdate{
		ChannelId: "mychannel",
		ReadSet: mkGroup("Admins", map[string][]byte{"BatchSize": []byte("10")}, map[string]*cb.ConfigGroup{
			"Application": mkGroup("Admins", map[string][]byte{"ACLs": []byte("acl1")}, nil),
		}),
		WriteSet: mkGroup("Admins", map[string][]byte{"BatchSize": []byte("20")}, map[string]*cb.ConfigGroup{
			"Application": mkGroup("Admins", map[string][]byte{"ACLs": []byte("acl2")}, nil),
		}),
	}

	// Seed 2: arbol mas ancho, 2 subgrupos hermanos.
	s2 := &cb.ConfigUpdate{
		ChannelId: "channel2",
		ReadSet: mkGroup("Readers", map[string][]byte{}, map[string]*cb.ConfigGroup{
			"Orderer":     mkGroup("Writers", map[string][]byte{"BatchTimeout": []byte("2s")}, nil),
			"Application": mkGroup("Writers", map[string][]byte{"Capabilities": []byte("V2_0")}, nil),
		}),
		WriteSet: mkGroup("Readers", map[string][]byte{}, map[string]*cb.ConfigGroup{
			"Orderer": mkGroup("Writers", map[string][]byte{"BatchTimeout": []byte("3s")}, nil),
		}),
	}

	// Seed 3: vacio (edge case real).
	s3 := &cb.ConfigUpdate{ChannelId: "empty", ReadSet: &cb.ConfigGroup{}, WriteSet: &cb.ConfigGroup{}}

	// Seed 4: 4 niveles reales de anidamiento.
	s4 := &cb.ConfigUpdate{
		ChannelId: "deepchannel",
		ReadSet: mkGroup("Admins", nil, map[string]*cb.ConfigGroup{
			"Consortiums": mkGroup("Admins", nil, map[string]*cb.ConfigGroup{
				"SampleConsortium": mkGroup("Admins", nil, map[string]*cb.ConfigGroup{
					"Org1MSP": mkGroup("Admins", map[string][]byte{"MSP": []byte("cert-bytes")}, nil),
				}),
			}),
		}),
		WriteSet: mkGroup("Admins", nil, map[string]*cb.ConfigGroup{
			"Consortiums": mkGroup("Admins", nil, map[string]*cb.ConfigGroup{
				"SampleConsortium": mkGroup("Admins", nil, map[string]*cb.ConfigGroup{
					"Org1MSP": mkGroup("Admins", map[string][]byte{"MSP": []byte("cert-bytes-2")}, nil),
				}),
			}),
		}),
	}

	return []*cb.ConfigUpdate{s1, s2, s3, s4}
}

// Formato REAL del corpus nativo de Go (`go test fuzz v1`, estable
// desde Go 1.18) -- %q en un []byte produce una string literal de Go
// valida y escapada de forma segura para cualquier byte.
func writeCorpusFile(path string, data []byte) error {
	content := fmt.Sprintf("go test fuzz v1\n[]byte(%q)\n", data)
	return os.WriteFile(path, []byte(content), 0644)
}

func main() {
	rngSeedArg := os.Args[1]
	baseDir := os.Args[2]
	treatDir := os.Args[3]

	var rngSeed int64
	fmt.Sscanf(rngSeedArg, "%d", &rngSeed)
	rng := rand.New(rand.NewSource(rngSeed))

	seeds := buildSeeds()

	os.MkdirAll(baseDir, 0755)
	os.MkdirAll(treatDir, 0755)

	for i, s := range seeds {
		data, err := proto.Marshal(s)
		if err != nil {
			panic(err)
		}
		for _, d := range []string{baseDir, treatDir} {
			p := filepath.Join(d, fmt.Sprintf("seed_%d", i))
			if err := writeCorpusFile(p, data); err != nil {
				panic(err)
			}
		}
	}

	for i := 0; i < 200; i++ {
		base := seeds[rng.Intn(len(seeds))]
		mutant := mutate(base, seeds, rng)
		data, err := proto.Marshal(mutant)
		if err != nil {
			panic(err)
		}
		p := filepath.Join(treatDir, fmt.Sprintf("mutant_%05d", i))
		if err := writeCorpusFile(p, data); err != nil {
			panic(err)
		}
	}

	fmt.Println("listo")
}
