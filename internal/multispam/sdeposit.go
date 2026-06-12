package multispam

import (
	"fmt"

	"github.com/lunfardo314/proxima/api/client"
	"github.com/lunfardo314/proxima/ledger"
	"github.com/lunfardo314/proxima/ledger/base"
	"github.com/lunfardo314/proxima/ledger/txbuildercore"
)

// MinStorageDepositSigLock computes, wallet-side, the minimum storage deposit
// for a standard sigLock output (the target and remainder outputs the spammer
// produces). The figure is evaluated by the node via the `storageDeposit($0)`
// schedule over the output's effective storage size — same method as
// `proxi node send`. All sigLock outputs the spammer produces share the same
// shape (one controller in the index-values tuple), so the result is a single
// dust floor reused for funding math and pre-submit validation.
//
// Note: tag-along outputs are storage-deposit exempt on the ledger side, so only
// the sigLock target/remainder outputs are subject to this floor.
func MinStorageDepositSigLock(lib *txbuildercore.Library[any], clnt *client.APIClient) (uint64, error) {
	// a representative sigLock output; the amount only affects size by a few
	// bytes (trimmed-uint64), which is immaterial to the deposit.
	var holder base.HolderID
	out, err := txbuildercore.NewSigLockOutput(lib, 1_000_000_000, holder)
	if err != nil {
		return 0, err
	}
	size := uint64(len(out.Bytes()))
	if ivBin, err := out.ConstraintAt(ledger.ConstraintIndexIndexValues); err == nil && len(ivBin) > 0 {
		values, verr := ledger.IndexValuesFromBytes(ivBin)
		if verr != nil {
			return 0, verr
		}
		// each index-values entry costs one trie row: length byte + value +
		// 33-byte UTXO ID. Mirrors ledger.effectiveStorageSize.
		size += uint64(len(ivBin)) + uint64(len(values))*33
	}
	return clnt.EvalU64(0, fmt.Sprintf("storageDeposit(u64/%d)", size))
}
