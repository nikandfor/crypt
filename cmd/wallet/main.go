package main

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/pbkdf2"
	"nikand.dev/go/cli"
	"nikand.dev/go/cli/flag"
	"tlog.app/go/errors"
	"tlog.app/go/tlog"
	"tlog.app/go/tlog/ext/tlflag"
)

var (
	bip43 uint32 = 44 + hdkeychain.HardenedKeyStart

	currencies = map[string]uint32{
		"btc":  0x80000000,
		"btct": 0x80000001,
		"ltc":  0x80000002,
		"doge": 0x80000003,
		"eth":  0x8000003c,
		"etc":  0x8000003d,
	}

	namedSegs = []map[string]uint32{
		{"": bip43, "bip43": bip43},
		currencies,
		nil,
		{"external": 0, "ext": 0, "e": 0, "internal": 1, "int": 1, "i": 1},
	}

	positionNames = []string{
		// "root"    // m or M
		"purpose",   // bip43
		"coin type", // btc
		"account",   // 0
		"change",    // internal or external
		"index",     // 0
	}
)

func main() {
	rawAddress := &cli.Command{
		Name:   "address",
		Args:   cli.Args{},
		Action: rawAddressRun,
	}

	btcrpc := &cli.Command{
		Name:   "rpc",
		Action: btcrpcRun,
		Flags: []*cli.Flag{
			cli.NewFlag("address", "", "base url"),
		},
	}

	btc := &cli.Command{
		Name: "btc",
		Commands: []*cli.Command{
			btcrpc,
		},
	}

	mnemonic := &cli.Command{
		Name:   "mnemonic",
		Action: mnemonicRun,
		Flags: []*cli.Flag{
			cli.NewFlag("size,s", 128, "size in words or bits"),
		},
	}

	app := &cli.Command{
		Name:   "wallet",
		Before: before,
		Flags: []*cli.Flag{
			cli.NewFlag("mnemonic,m", "", "mnemonic phrase"),
			cli.NewFlag("passphrase,password,p", "", "mnemonic passphrase"),

			cli.NewFlag("log", "stderr?dm", "log output file (or stderr)"),
			cli.NewFlag("verbosity,v", "", "logger verbosity topics"),
			cli.NewFlag("debug", "", "debug address", flag.Hidden),

			cli.FlagfileFlag,
			cli.HelpFlag,
		},
		Commands: []*cli.Command{
			btc,
			mnemonic,
			rawAddress,
		},
	}

	cli.RunAndExit(app, os.Args, os.Environ())
}

func before(c *cli.Command) error {
	w, err := tlflag.OpenWriter(c.String("log"))
	if err != nil {
		return errors.Wrap(err, "open log file")
	}

	tlog.DefaultLogger = tlog.New(w)

	tlog.SetVerbosity(c.String("verbosity"))

	return nil
}

func rawAddressRun(c *cli.Command) error {
	root, err := rootKey(c)
	if err != nil {
		return errors.Wrap(err, "get key")
	}

	for _, a := range c.Args {
		key, err := derive(root, a)
		if err != nil {
			return errors.Wrap(err, "derive %q", a)
		}

		pkey, err := key.Neuter()
		if err != nil {
			return errors.Wrap(err, "neuter %q", a)
		}

		tlog.V("key").Printw("key", "xpub", pkey)
		tlog.V("key").Printw("key", "xprv", key)

		prv, err := key.ECPrivKey()
		if err != nil {
			return errors.Wrap(err, "get priv key")
		}

		pub, err := key.ECPubKey()
		if err != nil {
			return errors.Wrap(err, "get pub key")
		}

		wif, err := btcutil.NewWIF(prv, &chaincfg.MainNetParams, true)
		if err != nil {
			return errors.Wrap(err, "make wif")
		}

		tlog.V("key").Printw("key", "pub", hex.EncodeToString(pub.SerializeCompressed()))
		tlog.V("key").Printw("key", "prv", hex.EncodeToString(prv.Serialize()))
		tlog.V("key").Printw("key", "wif", wif)

		addr, err := key.Address(&chaincfg.MainNetParams)
		if err != nil {
			return errors.Wrap(err, "get btc address")
		}

		tlog.Printw("btc address", "pkh", addr, "path", a)
	}

	return nil
}

func btcrpcRun(c *cli.Command) error {
	return nil
}

func mnemonicRun(c *cli.Command) error {
	size := c.Int("size")

	e, err := bip39.NewEntropy(size)
	if err != nil {
		return errors.Wrap(err, "new entropy")
	}

	s, err := bip39.NewMnemonic(e)
	if err != nil {
		return errors.Wrap(err, "new mnemonic")
	}

	nl := '\n'

	fmt.Printf("%s%c", s, nl)

	return nil
}

func derive(key *hdkeychain.ExtendedKey, path string) (*hdkeychain.ExtendedKey, error) {
	var err error

	first := next(path, 0, '/')

	switch {
	case key.Depth() != 0:
		// do nothing
	case path[:first] == "m":
		path = path[1:]
	case path[:first] == "M":
		key, err = key.Neuter()
		if err != nil {
			return nil, errors.Wrap(err, "neuter")
		}

		path = path[1:]
	default:
		return nil, errors.New("bad path")
	}

	for i, end := 0, 0; i < len(path); i = end {
		if path[i] == '/' {
			i++
		}

		end = next(path, i, '/')
		seg := path[i:end]

		neuter := len(seg) > 0 && seg[len(seg)-1] == '\''

		if neuter {
			seg = seg[:len(seg)-1]
		}

		d := key.Depth()

		//	tlog.Printw("seg", "d", d, "seg", seg)

		idx, ok := func() (uint32, bool) {
			if int(d) >= len(namedSegs) {
				return 0, false
			}

			named := namedSegs[d]

			idx, ok := named[strings.ToLower(seg)]

			return idx, ok
		}()

		if !ok {
			x, err := strconv.ParseUint(seg, 10, 32)
			if err != nil {
				return nil, errors.Wrap(err, "parse derive index")
			}

			idx = uint32(x)
		}

		if neuter {
			idx |= 1 << 31
		}

		key, err = key.Derive(idx)
		if err != nil {
			return nil, errors.Wrap(err, "direvi step %q", path[:end])
		}
	}

	return key, nil
}

func rootKey(c *cli.Command) (*hdkeychain.ExtendedKey, error) {
	mnemonic := c.String("mnemonic")
	pass := c.String("passphrase")

	mnemonic = normalizeMnemonic(mnemonic)

	if _, err := bip39.EntropyFromMnemonic(mnemonic); err != nil {
		return nil, errors.Wrap(err, "check mnemonic")
	}

	seed := pbkdf2.Key([]byte(mnemonic), append([]byte("mnemonic"), []byte(pass)...), 2048, 64, sha512.New)

	root, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, errors.Wrap(err, "new master key")
	}

	return root, nil
}

func normalizeMnemonic(s string) string {
	words := strings.Fields(s)

	return strings.Join(words, " ")
}

func next(s string, i int, r byte) int {
	for i < len(s) && s[i] != r {
		i++
	}

	return i
}
