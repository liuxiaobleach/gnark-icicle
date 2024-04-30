//go:build icicle

package icicle

import (
	"fmt"
	"math/big"
	"math/bits"
	"time"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/hash_to_field"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/pedersen"
	"github.com/consensys/gnark/backend"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/internal"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	fcs "github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/logger"
	icicle_core "github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	icicle_cr "github.com/ingonyama-zk/icicle/v2/wrappers/golang/cuda_runtime"
	icicle_bn254 "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254"
	icicle_g2 "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/g2"
	icicle_msm "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/msm"
	icicle_ntt "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/ntt"
)

const (
	device0 = 0
	device1 = 1
	device2 = 2
	device3 = 3
	device4 = 4
)

func (pk *ProvingKey) setupDevicePointersOnMulti() error {
	if pk.deviceInfo != nil {
		return nil
	}
	pk.deviceInfo = &deviceInfo{}
	gen, _ := fft.Generator(2 * pk.Domain.Cardinality)
	/*************************     Den      ***************************/
	n := int(pk.Domain.Cardinality)
	var denI, oneI fr.Element
	oneI.SetOne()
	denI.Exp(gen, big.NewInt(int64(pk.Domain.Cardinality)))
	denI.Sub(&denI, &oneI).Inverse(&denI)

	log2SizeFloor := bits.Len(uint(n)) - 1
	denIcicleArr := []fr.Element{denI}
	for i := 0; i < log2SizeFloor; i++ {
		denIcicleArr = append(denIcicleArr, denIcicleArr...)
	}
	pow2Remainder := n - 1<<log2SizeFloor
	for i := 0; i < pow2Remainder; i++ {
		denIcicleArr = append(denIcicleArr, denI)
	}

	copyDenDone := make(chan bool, 1)
	icicle_cr.RunOnDevice(device0, func(args ...any) {
		denIcicleArrHost := (icicle_core.HostSlice[fr.Element])(denIcicleArr)
		denIcicleArrHost.CopyToDevice(&pk.DenDevice, true)
		icicle_bn254.FromMontgomery(&pk.DenDevice)
		copyDenDone <- true
	})

	/*************************  Init Domain Device  ***************************/
	initNttDone := make(chan bool, 1)
	icicle_cr.RunOnDevice(device0, func(args ...any) {
		ctx, err := icicle_cr.GetDefaultDeviceContext()
		if err != icicle_cr.CudaSuccess {
			panic("Couldn't create device context") // TODO
		}

		genBits := gen.Bits()
		limbs := icicle_core.ConvertUint64ArrToUint32Arr(genBits[:])
		copy(pk.CosetGenerator[:], limbs[:fr.Limbs*2])
		var rouIcicle icicle_bn254.ScalarField
		rouIcicle.FromLimbs(limbs)
		e := icicle_ntt.InitDomain(rouIcicle, ctx, false)
		if e.IcicleErrorCode != icicle_core.IcicleSuccess {
			panic("Couldn't initialize domain") // TODO
		}
		initNttDone <- true
	})

	/*************************  End Init Domain Device  ***************************/
	/*************************  Start G1 Device Setup  ***************************/
	/*************************     A      ***************************/
	copyADone := make(chan bool, 1)
	icicle_cr.RunOnDevice(device1, func(args ...any) {
		g1AHost := (icicle_core.HostSlice[curve.G1Affine])(pk.G1.A)
		g1AHost.CopyToDevice(&pk.G1Device.A, true)
		copyADone <- true
	})
	/*************************     B      ***************************/
	copyBDone := make(chan bool, 1)
	icicle_cr.RunOnDevice(device0, func(args ...any) {
		g1BHost := (icicle_core.HostSlice[curve.G1Affine])(pk.G1.B)
		g1BHost.CopyToDevice(&pk.G1Device.B, true)
		copyBDone <- true
	})
	/*************************     K      ***************************/
	copyKDone := make(chan bool, 1)
	icicle_cr.RunOnDevice(device0, func(args ...any) {
		g1KHost := (icicle_core.HostSlice[curve.G1Affine])(pk.G1.K)
		g1KHost.CopyToDevice(&pk.G1Device.K, true)
		copyKDone <- true
	})
	/*************************     Z      ***************************/
	copyZDone := make(chan bool, 1)
	icicle_cr.RunOnDevice(device0, func(args ...any) {
		g1ZHost := (icicle_core.HostSlice[curve.G1Affine])(pk.G1.Z)
		g1ZHost.CopyToDevice(&pk.G1Device.Z, true)
		copyZDone <- true
	})
	/*************************  End G1 Device Setup  ***************************/
	<-copyDenDone
	<-copyADone
	<-copyBDone
	<-copyKDone
	<-copyZDone

	<-initNttDone
	/*************************  Start G2 Device Setup  ***************************/
	copyG2BDone := make(chan bool, 1)
	icicle_cr.RunOnDevice(device0, func(args ...any) {
		g2BHost := (icicle_core.HostSlice[curve.G2Affine])(pk.G2.B)
		g2BHost.CopyToDevice(&pk.G2Device.B, true)
		copyG2BDone <- true
	})

	<-copyG2BDone
	/*************************  End G2 Device Setup  ***************************/
	return nil
}

// Prove generates the proof of knowledge of a r1cs with full witness (secret + public part).
func ProveOnMulti(r1cs *cs.R1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*groth16_bn254.Proof, error) {
	log := logger.Logger().With().Str("curve", r1cs.CurveID().String()).Str("acceleration", "icicle").Int("nbConstraints", r1cs.GetNbConstraints()).Str("backend", "groth16").Logger()
	log.Debug().Msg("start ProveOnMulti")
	opt, err := backend.NewProverConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("new prover config: %w", err)
	}
	if opt.HashToFieldFn == nil {
		opt.HashToFieldFn = hash_to_field.New([]byte(constraint.CommitmentDst))
	}
	if pk.deviceInfo == nil {
		log.Debug().Msg("precomputing proving key on multi GPU")
		if err := pk.setupDevicePointersOnMulti(); err != nil {
			return nil, fmt.Errorf("setup device pointers: %w", err)
		}
	}

	commitmentInfo := r1cs.CommitmentInfo.(constraint.Groth16Commitments)

	proof := &groth16_bn254.Proof{Commitments: make([]curve.G1Affine, len(commitmentInfo))}

	solverOpts := opt.SolverOpts[:len(opt.SolverOpts):len(opt.SolverOpts)]

	privateCommittedValues := make([][]fr.Element, len(commitmentInfo))

	// override hints
	bsb22ID := solver.GetHintID(fcs.Bsb22CommitmentComputePlaceholder)
	solverOpts = append(solverOpts, solver.OverrideHint(bsb22ID, func(_ *big.Int, in []*big.Int, out []*big.Int) error {
		i := int(in[0].Int64())
		in = in[1:]
		privateCommittedValues[i] = make([]fr.Element, len(commitmentInfo[i].PrivateCommitted))
		hashed := in[:len(commitmentInfo[i].PublicAndCommitmentCommitted)]
		committed := in[+len(hashed):]
		for j, inJ := range committed {
			privateCommittedValues[i][j].SetBigInt(inJ)
		}

		var err error
		if proof.Commitments[i], err = pk.CommitmentKeys[i].Commit(privateCommittedValues[i]); err != nil {
			return err
		}

		opt.HashToFieldFn.Write(constraint.SerializeCommitment(proof.Commitments[i].Marshal(), hashed, (fr.Bits-1)/8+1))
		hashBts := opt.HashToFieldFn.Sum(nil)
		opt.HashToFieldFn.Reset()
		nbBuf := fr.Bytes
		if opt.HashToFieldFn.Size() < fr.Bytes {
			nbBuf = opt.HashToFieldFn.Size()
		}
		var res fr.Element
		res.SetBytes(hashBts[:nbBuf])
		res.BigInt(out[0])
		return nil
	}))

	_solution, err := r1cs.Solve(fullWitness, solverOpts...)
	if err != nil {
		return nil, err
	}

	solution := _solution.(*cs.R1CSSolution)
	wireValues := []fr.Element(solution.W)

	start := time.Now()

	commitmentsSerialized := make([]byte, fr.Bytes*len(commitmentInfo))
	for i := range commitmentInfo {
		copy(commitmentsSerialized[fr.Bytes*i:], wireValues[commitmentInfo[i].CommitmentIndex].Marshal())
	}

	if proof.CommitmentPok, err = pedersen.BatchProve(pk.CommitmentKeys, privateCommittedValues, commitmentsSerialized); err != nil {
		return nil, err
	}

	// H (witness reduction / FFT part)
	var h icicle_core.DeviceSlice
	chHDone := make(chan struct{}, 1)
	icicle_cr.RunOnDevice(device0, func(args ...any) {
		h = computeH(solution.A, solution.B, solution.C, pk, log)

		solution.A = nil
		solution.B = nil
		solution.C = nil
		chHDone <- struct{}{}
	})

	// we need to copy and filter the wireValues for each multi exp
	// as pk.G1.A, pk.G1.B and pk.G2.B may have (a significant) number of point at infinity
	var wireValuesADevice, wireValuesBDevice icicle_core.DeviceSlice
	chWireValuesA, chWireValuesB := make(chan struct{}, 1), make(chan struct{}, 1)

	icicle_cr.RunOnDevice(device1, func(args ...any) {
		wireValuesA := make([]fr.Element, len(wireValues)-int(pk.NbInfinityA))
		for i, j := 0, 0; j < len(wireValuesA); i++ {
			if pk.InfinityA[i] {
				continue
			}
			wireValuesA[j] = wireValues[i]
			j++
		}

		// Copy scalars to the device and retain ptr to them
		wireValuesAHost := (icicle_core.HostSlice[fr.Element])(wireValuesA)
		wireValuesAHost.CopyToDevice(&wireValuesADevice, true)

		close(chWireValuesA)
	})
	icicle_cr.RunOnDevice(device0, func(args ...any) {
		wireValuesB := make([]fr.Element, len(wireValues)-int(pk.NbInfinityB))
		for i, j := 0, 0; j < len(wireValuesB); i++ {
			if pk.InfinityB[i] {
				continue
			}
			wireValuesB[j] = wireValues[i]
			j++
		}

		// Copy scalars to the device and retain ptr to them
		wireValuesBHost := (icicle_core.HostSlice[fr.Element])(wireValuesB)
		wireValuesBHost.CopyToDevice(&wireValuesBDevice, true)

		close(chWireValuesB)
	})

	// sample random r and s
	var r, s big.Int
	var _r, _s, _kr fr.Element
	if _, err := _r.SetRandom(); err != nil {
		return nil, err
	}
	if _, err := _s.SetRandom(); err != nil {
		return nil, err
	}
	_kr.Mul(&_r, &_s).Neg(&_kr)

	_r.BigInt(&r)
	_s.BigInt(&s)

	// computes r[δ], s[δ], kr[δ]
	deltas := curve.BatchScalarMultiplicationG1(&pk.G1.Delta, []fr.Element{_r, _s, _kr})

	var bs1, ar curve.G1Jac

	computeBS1 := func() error {
		<-chWireValuesB

		cfg := icicle_msm.GetDefaultMSMConfig()
		cfg.ArePointsMontgomeryForm = true
		cfg.AreScalarsMontgomeryForm = true
		res := make(icicle_core.HostSlice[icicle_bn254.Projective], 1)
		start := time.Now()
		icicle_msm.Msm(wireValuesBDevice, pk.G1Device.B, &cfg, res)
		log.Debug().Dur("took", time.Since(start)).Msg("MSM Bs1")
		bs1 = g1ProjectiveToG1Jac(res[0])

		bs1.AddMixed(&pk.G1.Beta)
		bs1.AddMixed(&deltas[1])

		return nil
	}

	computeAR1 := func() error {
		<-chWireValuesA

		cfg := icicle_msm.GetDefaultMSMConfig()
		cfg.ArePointsMontgomeryForm = true
		cfg.AreScalarsMontgomeryForm = true
		res := make(icicle_core.HostSlice[icicle_bn254.Projective], 1)
		start := time.Now()
		icicle_msm.Msm(wireValuesADevice, pk.G1Device.A, &cfg, res)
		log.Debug().Dur("took", time.Since(start)).Msg("MSM Ar1")
		ar = g1ProjectiveToG1Jac(res[0])

		ar.AddMixed(&pk.G1.Alpha)
		ar.AddMixed(&deltas[0])
		proof.Ar.FromJacobian(&ar)

		return nil
	}

	computeKRS := func() error {
		var krs, krs2, p1 curve.G1Jac
		sizeH := int(pk.Domain.Cardinality - 1)

		cfg := icicle_msm.GetDefaultMSMConfig()
		cfg.ArePointsMontgomeryForm = true
		cfg.AreScalarsMontgomeryForm = true
		resKrs2 := make(icicle_core.HostSlice[icicle_bn254.Projective], 1)
		start := time.Now()
		icicle_msm.Msm(h.RangeTo(sizeH, false), pk.G1Device.Z, &cfg, resKrs2)
		log.Debug().Dur("took", time.Since(start)).Msg("MSM Krs2")
		krs2 = g1ProjectiveToG1Jac(resKrs2[0])

		// filter the wire values if needed
		// TODO Perf @Tabaie worst memory allocation offender
		toRemove := commitmentInfo.GetPrivateCommitted()
		toRemove = append(toRemove, commitmentInfo.CommitmentIndexes())
		_wireValues := filterHeap(wireValues[r1cs.GetNbPublicVariables():], r1cs.GetNbPublicVariables(), internal.ConcatAll(toRemove...))
		_wireValuesHost := (icicle_core.HostSlice[fr.Element])(_wireValues)
		resKrs := make(icicle_core.HostSlice[icicle_bn254.Projective], 1)
		start = time.Now()
		icicle_msm.Msm(_wireValuesHost, pk.G1Device.K, &cfg, resKrs)
		log.Debug().Dur("took", time.Since(start)).Msg("MSM Krs")
		krs = g1ProjectiveToG1Jac(resKrs[0])

		krs.AddMixed(&deltas[2])

		krs.AddAssign(&krs2)

		p1.ScalarMultiplication(&ar, &s)
		krs.AddAssign(&p1)

		p1.ScalarMultiplication(&bs1, &r)
		krs.AddAssign(&p1)

		proof.Krs.FromJacobian(&krs)

		return nil
	}

	computeBS2 := func() error {
		// Bs2 (1 multi exp G2 - size = len(wires))
		var Bs, deltaS curve.G2Jac

		<-chWireValuesB

		cfg := icicle_g2.G2GetDefaultMSMConfig()
		cfg.ArePointsMontgomeryForm = true
		cfg.AreScalarsMontgomeryForm = true
		res := make(icicle_core.HostSlice[icicle_g2.G2Projective], 1)
		start := time.Now()
		icicle_g2.G2Msm(wireValuesBDevice, pk.G2Device.B, &cfg, res)
		log.Debug().Dur("took", time.Since(start)).Msg("MSM Bs2 G2")
		Bs = g2ProjectiveToG2Jac(&res[0])

		deltaS.FromAffine(&pk.G2.Delta)
		deltaS.ScalarMultiplication(&deltaS, &s)
		Bs.AddAssign(&deltaS)
		Bs.AddMixed(&pk.G2.Beta)

		proof.Bs.FromJacobian(&Bs)
		return nil
	}

	// wait for FFT to end
	<-chHDone

	// schedule our proof part computations
	arDone := make(chan error, 1)
	icicle_cr.RunOnDevice(device1, func(args ...any) {
		arDone <- computeAR1()
	})
	<-arDone

	BS1Done := make(chan error, 1)
	icicle_cr.RunOnDevice(device0, func(args ...any) {
		BS1Done <- computeBS1()
	})
	<-BS1Done

	KRSDone := make(chan error, 1)
	icicle_cr.RunOnDevice(device0, func(args ...any) {
		KRSDone <- computeKRS()
	})
	<-KRSDone

	BS2Done := make(chan error, 1)
	icicle_cr.RunOnDevice(device0, func(args ...any) {
		BS2Done <- computeBS2()
	})
	<-BS2Done

	log.Debug().Dur("took", time.Since(start)).Msg("prover done")

	// free device/GPU memory that is not needed for future proofs (scalars/hpoly)
	freeADone := make(chan error, 1)
	icicle_cr.RunOnDevice(device1, func(args ...any) {
		wireValuesADevice.Free()
		freeADone <- nil
	})
	freeBDone := make(chan error, 1)
	icicle_cr.RunOnDevice(device0, func(args ...any) {
		wireValuesBDevice.Free()
		h.Free()
		freeBDone <- nil
	})
	<-freeADone
	<-freeBDone
	return proof, nil
}
