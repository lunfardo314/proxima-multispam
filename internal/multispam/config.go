package multispam

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/lunfardo314/proxima/ledger"
	"github.com/lunfardo314/proxima/ledger/base"
	"github.com/lunfardo314/proxima/util/keystore"
	"gopkg.in/yaml.v3"
)

type HostConfig struct {
	URL     string        `yaml:"url"`
	Timeout time.Duration `yaml:"timeout"`
}

type GlobalConfig struct {
	TransferAmount       uint64 `yaml:"transfer_amount"`
	FinalityTimeoutSlots int    `yaml:"finality_timeout_slots"`
	BatchSize            int    `yaml:"batch_size"`
	TargetStrategy       string `yaml:"target_strategy"`
	SequencerStrategy    string `yaml:"sequencer_strategy"`     // "next" (round-robin) or "random"
	HostStrategy         string `yaml:"host_strategy"`          // "next" (round-robin) or "random"
	// RebalanceIntervalSlots throttles the rich-sender fan-out funding (rebalance mode):
	// a sender does at most one fan-out every this many slots. Fan-out funding lands in
	// the LRB only after finalization, so re-funding every round acts on stale balances
	// and re-condenses; spacing it lets balances settle before the next decision.
	RebalanceIntervalSlots int `yaml:"rebalance_interval_slots"`
	MindRateControl      *bool  `yaml:"mind_rate_control"`      // default true: wait pace duration between rounds
	TimestampJitterTicks *int   `yaml:"timestamp_jitter_ticks"` // random ticks added to each tx timestamp to spread them across the slot; nil=default (one slot), 0=off
}

type SenderConfig struct {
	Name    string `yaml:"name"`
	KeyFile string `yaml:"key_file"`
}

type Config struct {
	APIHosts []HostConfig `yaml:"api_hosts"`
	Global   GlobalConfig `yaml:"global"`
	Senders  []SenderConfig `yaml:"senders"`
}

const (
	DefaultConfigFile          = "multispam.yaml"
	DefaultTransferAmount      = 100_000_000
	DefaultFinalityTimeoutSlots = 3
	DefaultBatchSize           = 1
	// DefaultRebalanceIntervalSlots spaces fan-out funding so balances finalize in the
	// LRB between decisions (finality is a few slots); re-funding every round on stale
	// balances re-condenses the distribution.
	DefaultRebalanceIntervalSlots = 5
	DefaultTargetStrategy       = "self"
	DefaultSequencerStrategy    = "next"
	DefaultHostStrategy         = "random"
	DefaultHostTimeout          = 10 * time.Second
	// DefaultTimestampJitterTicks spreads tx timestamps over roughly one slot
	// so they don't cluster on the current clock tick / slot boundary.
	DefaultTimestampJitterTicks = base.TicksPerSlot

	StrategyS         = "self"
	StrategyNext      = "next"
	StrategyRandom    = "random"
	StrategyRebalance = "rebalance" // target a below-average sender so spam traffic evens the distribution
)

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("can't read config file '%s': %v", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("can't parse config file '%s': %v", path, err)
	}
	cfg.applyDefaults()
	return &cfg, cfg.validate()
}

func (cfg *Config) IsMindRateControl() bool {
	return cfg.Global.MindRateControl == nil || *cfg.Global.MindRateControl
}

// JitterTicks returns the number of random ticks to add on top of each tx's
// minimum (pace-respecting) timestamp. nil means use the default; 0 disables
// jitter (timestamps then pin to the clock tick, as before).
func (cfg *Config) JitterTicks() int {
	if cfg.Global.TimestampJitterTicks == nil {
		return DefaultTimestampJitterTicks
	}
	return *cfg.Global.TimestampJitterTicks
}

// MinBalanceForOneTx is the minimum spendable balance a sender needs to build a
// single valid transfer that does not create a dust remainder: one transfer, the
// tag-along fee, and a remainder that still clears the sigLock storage-deposit
// floor. A remainder below minStorageDeposit makes the whole transaction invalid
// (the node rejects it with "storage deposit not met"), so this floor is the real
// gate, not just transfer+fee.
func (cfg *Config) MinBalanceForOneTx(tagAlongFee, minStorageDeposit uint64) uint64 {
	return cfg.Global.TransferAmount + tagAlongFee + minStorageDeposit
}

// MinFundingPerSender is the balance a sender needs to run one full batch round
// without producing a dust (sub-storage-deposit) output: batch_size transfers,
// a single tag-along fee (charged once, on the last tx in the batch), plus a
// final remainder that still clears the storage-deposit floor. This is the
// figure to fund each sender with; it is batch-size and storage-deposit
// dependent.
func (cfg *Config) MinFundingPerSender(tagAlongFee, minStorageDeposit uint64) uint64 {
	return uint64(cfg.Global.BatchSize)*cfg.Global.TransferAmount + tagAlongFee + minStorageDeposit
}

func (cfg *Config) applyDefaults() {
	if cfg.Global.TransferAmount == 0 {
		cfg.Global.TransferAmount = DefaultTransferAmount
	}
	if cfg.Global.FinalityTimeoutSlots <= 0 {
		cfg.Global.FinalityTimeoutSlots = DefaultFinalityTimeoutSlots
	}
	if cfg.Global.BatchSize <= 0 {
		cfg.Global.BatchSize = DefaultBatchSize
	}
	if cfg.Global.RebalanceIntervalSlots <= 0 {
		cfg.Global.RebalanceIntervalSlots = DefaultRebalanceIntervalSlots
	}
	if cfg.Global.TargetStrategy == "" {
		cfg.Global.TargetStrategy = DefaultTargetStrategy
	}
	if cfg.Global.SequencerStrategy == "" {
		cfg.Global.SequencerStrategy = DefaultSequencerStrategy
	}
	if cfg.Global.HostStrategy == "" {
		cfg.Global.HostStrategy = DefaultHostStrategy
	}
	for i := range cfg.APIHosts {
		if cfg.APIHosts[i].Timeout == 0 {
			cfg.APIHosts[i].Timeout = DefaultHostTimeout
		}
	}
}

func (cfg *Config) validate() error {
	if len(cfg.APIHosts) == 0 {
		return fmt.Errorf("at least one API host required")
	}
	if len(cfg.Senders) < 2 {
		return fmt.Errorf("at least 2 senders required, got %d", len(cfg.Senders))
	}
	switch cfg.Global.TargetStrategy {
	case StrategyS, StrategyNext, StrategyRandom, StrategyRebalance:
	default:
		return fmt.Errorf("unknown target_strategy: '%s' (expected self, next, random, rebalance)", cfg.Global.TargetStrategy)
	}
	switch cfg.Global.SequencerStrategy {
	case StrategyNext, StrategyRandom:
	default:
		return fmt.Errorf("unknown sequencer_strategy: '%s' (expected next, random)", cfg.Global.SequencerStrategy)
	}
	switch cfg.Global.HostStrategy {
	case StrategyNext, StrategyRandom:
	default:
		return fmt.Errorf("unknown host_strategy: '%s' (expected next, random)", cfg.Global.HostStrategy)
	}
	for i, s := range cfg.Senders {
		if s.Name == "" {
			return fmt.Errorf("sender %d has empty name", i)
		}
		if s.KeyFile == "" {
			return fmt.Errorf("sender '%s' has empty key_file", s.Name)
		}
	}
	return nil
}

// LoadSenderKey loads the private key from a sender's key file (unencrypted only for multispam).
func LoadSenderKey(keyFile string) (ed25519.PrivateKey, error) {
	ks, err := keystore.LoadFromFile(keyFile)
	if err != nil {
		return nil, err
	}
	if ks.IsEncrypted() {
		return nil, fmt.Errorf("encrypted key files not supported for multispam senders (file: %s)", keyFile)
	}
	privBytes, err := ks.GetPrivateKey("")
	if err != nil {
		return nil, err
	}
	return ed25519.PrivateKey(privBytes), nil
}

// SenderAddress returns the SigLock address for a sender's key file.
func SenderAddress(keyFile string) (ledger.SigLock, error) {
	ks, err := keystore.LoadFromFile(keyFile)
	if err != nil {
		return ledger.SigLock{}, err
	}
	pubKeyBytes, err := keystore.PublicKeyBytes(ks)
	if err != nil {
		return ledger.SigLock{}, err
	}
	return ledger.SigLockFromED25519PublicKey(ed25519.PublicKey(pubKeyBytes)), nil
}

// SenderHolderID returns the holder ID hex string for a sender's key file.
func SenderHolderID(keyFile string) (string, error) {
	ks, err := keystore.LoadFromFile(keyFile)
	if err != nil {
		return "", err
	}
	return ks.HolderID, nil
}

// GenerateDefaultConfig creates a config file with N senders and default values.
func GenerateDefaultConfig(numSenders int, apiHost string, keyDir string) *Config {
	jitter := DefaultTimestampJitterTicks
	cfg := &Config{
		APIHosts: []HostConfig{
			{URL: apiHost, Timeout: DefaultHostTimeout},
		},
		Global: GlobalConfig{
			TransferAmount:       DefaultTransferAmount,
			FinalityTimeoutSlots: DefaultFinalityTimeoutSlots,
			BatchSize:            DefaultBatchSize,
			TargetStrategy:       DefaultTargetStrategy,
			SequencerStrategy:    DefaultSequencerStrategy,
			HostStrategy:         DefaultHostStrategy,
			TimestampJitterTicks: &jitter,
		},
		Senders: make([]SenderConfig, numSenders),
	}
	for i := 0; i < numSenders; i++ {
		cfg.Senders[i] = SenderConfig{
			Name:    fmt.Sprintf("sender%d", i+1),
			KeyFile: fmt.Sprintf("%s/sender%d.key", keyDir, i+1),
		}
	}
	return cfg
}

// SaveConfig writes the config to a YAML file.
func SaveConfig(cfg *Config, path string) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}
	return os.WriteFile(path, data, 0644)
}

// GenerateAndSaveKey generates an ED25519 key pair and saves it as an unencrypted keystore file.
// Returns the holder ID hex string.
func GenerateAndSaveKey(path string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", fmt.Errorf("failed to generate key: %v", err)
	}
	holderID := base.HolderIDFromPublicKey(base.SignatureTypeED25519, pub)
	holderIDHex := hex.EncodeToString(holderID[:])
	ks, err := keystore.NewUnencrypted(keystore.KeyTypeED25519, priv, pub, holderIDHex)
	if err != nil {
		return "", err
	}
	if err := ks.SaveToFile(path); err != nil {
		return "", err
	}
	return holderIDHex, nil
}
