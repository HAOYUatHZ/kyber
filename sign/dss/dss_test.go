package dss

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	dkg "go.dedis.ch/kyber/v3/share/dkg/rabin"
	"go.dedis.ch/kyber/v3/sign/eddsa"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/kyber/v3/util/encoding"
)

var suite = edwards25519.NewBlakeSHA256Ed25519()

var nbParticipants = 7
var t = nbParticipants/2 + 1

var partPubs []kyber.Point
var partSec []kyber.Scalar

var longterms []*dkg.DistKeyShare
var randoms []*dkg.DistKeyShare

var dss []*DSS

func init() {
	partPubs = make([]kyber.Point, nbParticipants)
	partSec = make([]kyber.Scalar, nbParticipants)
	for i := 0; i < nbParticipants; i++ {
		sec, pub := genPair(i)
		partPubs[i] = pub
		partSec[i] = sec
	}
	longterms = genDistSecret()
	randoms = genDistSecret()
}

func TestDSSNew(t *testing.T) {
	dss, err := NewDSS(suite, partSec[0], partPubs, longterms[0], randoms[0], []byte("hello3"), 4)
	assert.NotNil(t, dss)
	assert.Nil(t, err)

	dss, err = NewDSS(suite, suite.Scalar().Zero(), partPubs, longterms[0], randoms[0], []byte("hello3"), 4)
	assert.Nil(t, dss)
	assert.Error(t, err)
}

func TestDSSPartialSigs(t *testing.T) {
	dss0 := getDSS(0)
	dss1 := getDSS(1)
	ps0, err := dss0.PartialSig()
	assert.Nil(t, err)
	assert.NotNil(t, ps0)
	assert.Len(t, dss0.partials, 1)
	// second time should not affect list
	ps0, err = dss0.PartialSig()
	assert.Nil(t, err)
	assert.NotNil(t, ps0)
	assert.Len(t, dss0.partials, 1)

	// wrong index
	goodI := ps0.Partial.I
	ps0.Partial.I = 100
	assert.Error(t, dss1.ProcessPartialSig(ps0))
	ps0.Partial.I = goodI

	// wrong Signature
	goodSig := ps0.Signature
	ps0.Signature = randomBytes(len(ps0.Signature))
	assert.Error(t, dss1.ProcessPartialSig(ps0))
	ps0.Signature = goodSig

	// invalid partial sig
	goodV := ps0.Partial.V
	ps0.Partial.V = suite.Scalar().Zero()
	ps0.Signature, err = schnorr.Sign(suite, dss0.secret, ps0.Hash(suite))
	require.Nil(t, err)
	err = dss1.ProcessPartialSig(ps0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not valid")
	ps0.Partial.V = goodV
	ps0.Signature = goodSig

	// fine
	err = dss1.ProcessPartialSig(ps0)
	assert.Nil(t, err)

	// already received
	assert.Error(t, dss1.ProcessPartialSig(ps0))

	// if not enough partial signatures, can't generate signature
	buff, err := dss1.Signature()
	assert.Nil(t, buff)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not enough")

	// enough partial sigs ?
	for i := 2; i < nbParticipants; i++ {
		dss := getDSS(i)
		ps, err := dss.PartialSig()
		require.Nil(t, err)
		require.Nil(t, dss1.ProcessPartialSig(ps))
	}
	assert.True(t, dss1.EnoughPartialSig())
}

func TestDSSSignature(t *testing.T) {
	dsss := make([]*DSS, nbParticipants)
	pss := make([]*PartialSig, nbParticipants)
	for i := 0; i < nbParticipants; i++ {
		dsss[i] = getDSS(i)
		ps, err := dsss[i].PartialSig()
		require.Nil(t, err)
		require.NotNil(t, ps)
		pss[i] = ps
	}
	for i, dss := range dsss {
		for j, ps := range pss {
			if i == j {
				continue
			}
			require.Nil(t, dss.ProcessPartialSig(ps))
		}
	}
	// issue and verify signature
	dss0 := dsss[0]
	buff, err := dss0.Signature()
	assert.NotNil(t, buff)
	assert.Nil(t, err)
	err = eddsa.Verify(longterms[0].Public(), dss0.msg, buff)
	assert.Nil(t, err)
	assert.Nil(t, Verify(longterms[0].Public(), dss0.msg, buff))
}

func getDSS(i int) *DSS {
	dss, err := NewDSS(suite, partSec[i], partPubs, longterms[i], randoms[i], []byte("hello3"), t)
	if dss == nil || err != nil {
		panic("nil dss")
	}
	return dss
}

func genDistSecret() []*dkg.DistKeyShare {
	dkgs := make([]*dkg.DistKeyGenerator, nbParticipants)
	for i := 0; i < nbParticipants; i++ {
		dkg, err := dkg.NewDistKeyGenerator(suite, partSec[i], partPubs, nbParticipants/2+1)
		if err != nil {
			panic(err)
		}
		dkgs[i] = dkg
	}
	// full secret sharing exchange
	// 1. broadcast deals
	resps := make([]*dkg.Response, 0, nbParticipants*nbParticipants)
	for _, dkg := range dkgs {
		deals, err := dkg.Deals()
		if err != nil {
			panic(err)
		}
		for i, d := range deals {
			resp, err := dkgs[i].ProcessDeal(d)
			if err != nil {
				panic(err)
			}
			if !resp.Response.Approved {
				panic("wrong approval")
			}
			resps = append(resps, resp)
		}
	}
	// 2. Broadcast responses
	for _, resp := range resps {
		for h, dkg := range dkgs {
			// ignore all messages from ourself
			if resp.Response.Index == uint32(h) {
				continue
			}
			j, err := dkg.ProcessResponse(resp)
			if err != nil || j != nil {
				panic("wrongProcessResponse")
			}
		}
	}
	// 4. Broadcast secret commitment
	for i, dkg := range dkgs {
		scs, err := dkg.SecretCommits()
		if err != nil {
			panic("wrong SecretCommits")
		}
		for j, dkg2 := range dkgs {
			if i == j {
				continue
			}
			cc, err := dkg2.ProcessSecretCommits(scs)
			if err != nil || cc != nil {
				panic("wrong ProcessSecretCommits")
			}
		}
	}

	// 5. reveal shares
	dkss := make([]*dkg.DistKeyShare, len(dkgs))
	for i, dkg := range dkgs {
		dks, err := dkg.DistKeyShare()
		if err != nil {
			panic(err)
		}
		dkss[i] = dks
	}

	cmmhexs := make([]string, 4)
	cmmhexs[0] = "a73b1c6e5f47883c46cd84ea2cdf4af9b6fbed42448fca6d0a0c4044ac9062e3"
	cmmhexs[1] = "ad7d60b53bebe7354f15e7b11cd64a43f8da78e9df60a2b6237fd9dce471a6da"
	cmmhexs[2] = "55c20d16559d25be0725e316a778bc5834b91ddae41fcfcdeb656d1ada8054df"
	cmmhexs[3] = "7dc1725605bd25abae21309dfecb0373767e3cb5e8a29e0d714c0e444b1ec684"
	ponits := make([]kyber.Point, 4)
	var err error
	for i := 0; i < 4; i++ {
		ponits[i], err = encoding.StringHexToPoint(new(edwards25519.Curve), cmmhexs[i])
		if err != nil {
			panic(err)
		}
	}

	prvhexs := make([]string, 7)
	prvhexs[0] = "54b19ee1b3fe0d0306f5fe596c0d4da745fbaefc53f6f02898a2bb67ac999002"
	prvhexs[1] = "03cef8ce4920dd0d54ee0f8f0e077bd7e554d2004a92436d33bbded709c4500e"
	prvhexs[2] = "a9baa5074f04262fd5adec2cb908365d0c776e01cffe54a2cf9194a391b88f0a"
	prvhexs[3] = "3b9f812f2bdcc3e1275788851518ba5c7c78e40605ab93355f8148b4be5efc09"
	prvhexs[4] = "c1cf728d2b767f481471de47ee4064e5f86f95190e066e94d4e465f30b9e450f"
	prvhexs[5] = "56cc690b833d0f2e8ce5f27f2f95b2f14474e2410c7f522c2217584af45d1a0d"
	prvhexs[6] = "02e94cf07e003cb5573bc1dca3200291239c2c882185af6a3a738aa2f2852906"

	for i := 0; i < len(dkss); i++ {
		dkss[i].Commits = ponits
		dkss[i].Share.I = i
		dkss[i].Share.V, err = encoding.StringHexToScalar(new(edwards25519.Curve), prvhexs[i])
		if err != nil {
			panic(err)
		}

		fmt.Println("longterm?", i, dkss[i].Public())
	}

	return dkss
}

func genPair(i int) (kyber.Scalar, kyber.Point) {
	// sc := suite.Scalar().Pick(suite.RandomStream())
	// return sc, suite.Point().Mul(sc, nil)
	prvKeyStr := "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f6"
	seed, err := hex.DecodeString(fmt.Sprintf("%s%d", prvKeyStr, i))
	if err != nil {
		panic(err)
	}

	group := new(edwards25519.Curve)
	secret, _, _ := group.NewKeyAndSeedWithInput(seed)
	public := group.Point().Mul(secret, nil)
	fmt.Println(i, public)
	return secret, public
}

func randomBytes(n int) []byte {
	var buff = make([]byte, n)
	_, _ = rand.Read(buff[:])
	return buff
}
