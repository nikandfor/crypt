package main

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/pkg/errors"
	bip39 "github.com/tyler-smith/go-bip39"
	cli "gopkg.in/urfave/cli.v2"
)

var root *hdkeychain.ExtendedKey

var (
	BIP43      uint32 = 44 + hdkeychain.HardenedKeyStart
	currencies        = map[string]uint32{
		"btc":  0x80000000,
		"btct": 0x80000001,
		"ltc":  0x80000002,
		"doge": 0x80000003,
		"eth":  0x8000003c,
		"etc":  0x8000003d,
	}
)

var (
	positionNames = map[int]string{
		0: "root",
		1: "purpose",
		2: "coin type",
		3: "account",
		4: "change",
		5: "index",
	}
)

func main() {
	var app cli.App
	app.Commands = []*cli.Command{
		{
			Name:        "address",
			Usage:       "<path> (example: /btc/acc'/0/123)",
			Description: "calculates address",
			Action:      address,
			Flags: []cli.Flag{
				&cli.BoolFlag{Name: "priv", Aliases: []string{"p"}, Value: false},
			},
			Before: initKey,
		},
		{
			Name:        "mnemonic",
			Usage:       "",
			Description: "generates mnemonic",
			Action:      genMnemonic,
			Flags: []cli.Flag{
				&cli.IntFlag{Name: "size"},
			},
		},
	}
	app.Flags = []cli.Flag{
		&cli.StringFlag{Name: "mnemonic", Aliases: []string{"m"}},
		&cli.StringFlag{Name: "pass", Aliases: []string{"p"}},
		&cli.StringFlag{Name: "seed", Aliases: []string{"s"}},
	}

	app.Run(os.Args)
}

func initKey(c *cli.Context) error {
	if seed := c.String("seed"); len(seed) != 0 {
		switch len(seed) {
		case 2 * hdkeychain.RecommendedSeedLen:
		case 128:
		default:
			return fmt.Errorf("unexpected seed len: %d", len(seed))
		}
		b := make([]byte, len(seed)/2)
		n, err := hex.Decode(b, []byte(seed))
		if err != nil {
			return errors.Wrap(err, "decode seed from hex")
		}
		if n != len(b) {
			return errors.Wrapf(err, "decoded %d bytes (want %d)", n, len(b))
		}

		return generateKey(b)
	}

	pass := c.String("pass")
	mnemonic := c.String("mnemonic")
	if !bip39.IsMnemonicValid(mnemonic) {
		return errors.New("mnemonic is invalid")
	}
	mnemonic = normalizeMnemonic(mnemonic)

	seed := pbkdf2.Key([]byte(mnemonic), append([]byte("mnemonic"), []byte(pass)...), 2048, 64, sha512.New)

	return generateKey(seed)
}

func generateKey(seed []byte) (err error) {
	root, err = hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	return
}

func address(c *cli.Context) (err error) {
	path := c.Args().First()

	k, err := deriviate(root, path)
	if err != nil {
		return err
	}

	return printkey(c, k)
}

func deriviate(key *hdkeychain.ExtendedKey, path string) (k *hdkeychain.ExtendedKey, err error) {
	if path == "" {
		return nil, errors.New("empty path")
	}
	k = key
	p := strings.Split(path, "/")

	switch p[0] {
	case "m":
	case "M":
		k, err = k.Neuter()
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("path must be started from m or M")
	}

	if len(p) == 1 {
		return
	}

	step := func(s string) error {
		var hardened bool
		if strings.HasSuffix(s, "'") {
			s = s[:len(s)-1]
			hardened = true
		}

		var child uint32
		if strings.HasPrefix(s, "#") {
			s = s[1:]
			child = crc32.ChecksumIEEE([]byte(s))
		} else if val, err := strconv.Atoi(s); err == nil {
			child = uint32(val)
		} else {
			return fmt.Errorf("expected number or hash, found `%v'", s)
		}
		if hardened {
			child |= 0x80000000
		} else {
			child &^= 0x80000000
		}

		k, err = k.Child(child)
		return err
	}

	// purpose
	switch p[1] {
	case "", "bip43", "BIP43":
		k, err = k.Child(BIP43)
		if err != nil {
			return nil, err
		}
	default:
		if err = step(p[1]); err != nil {
			return nil, errors.Wrap(err, "expected purpose")
		}
	}

	if len(p) == 2 {
		return
	}

	// coin type
	if cur, ok := currencies[p[2]]; ok {
		k, err = k.Child(cur)
		if err != nil {
			return nil, err
		}
	} else {
		if err = step(p[2]); err != nil {
			return nil, errors.Wrap(err, "expected coin type")
		}
	}

	if len(p) == 3 {
		return
	}

	// account
	if err = step(p[3]); err != nil {
		return nil, errors.Wrap(err, "expected account")
	}

	if len(p) == 4 {
		return
	}

	// change
	switch p[4] {
	case "e", "ext", "external":
		k, err = k.Child(0)
		if err != nil {
			return nil, err
		}
	case "i", "in", "internal":
		k, err = k.Child(1)
		if err != nil {
			return nil, err
		}
	default:
		if err = step(p[4]); err != nil {
			return nil, errors.Wrap(err, "expected change")
		}
	}

	// index
	for i := 5; i < len(p); i++ {
		if err = step(p[i]); err != nil {
			return nil, errors.Wrap(err, "expected (sub)index")
		}
	}

	return
}

func printkey(c *cli.Context, k *hdkeychain.ExtendedKey) (err error) {
	addr, err := k.Address(&chaincfg.MainNetParams)
	if err != nil {
		return err
	}
	fmt.Printf("address: %v\n", addr)

	prv, err := k.ECPrivKey()
	if err != nil {
		return err
	}
	pub, err := k.ECPubKey()
	if err != nil {
		return err
	}

	wif, err := btcutil.NewWIF(prv, &chaincfg.MainNetParams, false)
	if err != nil {
		return err
	}

	fmt.Printf("WIF: %v\n", wif)

	fmt.Printf("privatehex: %v\n", hex.EncodeToString(prv.Serialize()))
	fmt.Printf("publichex : %v\n", hex.EncodeToString(pub.SerializeHybrid()))

	fmt.Printf("private58: %v\n", base58.Encode(prv.Serialize()))
	fmt.Printf("public58 : %v\n", base58.Encode(pub.SerializeHybrid()))

	n, err := k.Neuter()
	if err != nil {
		return err
	}

	fmt.Println(k)
	fmt.Println(n)

	return nil
}

func normalizeMnemonic(s string) string {
	w := strings.Fields(s)
	return strings.Join(w, " ")
}

func genMnemonic(c *cli.Context) error {
	size := c.Int("size")
	if size%32 != 0 {
		return errors.New("wrong entropy len (ENT), must be multiple of 32 bits")
	}

	e, err := bip39.NewEntropy(size)
	if err != nil {
		panic(err)
	}

	s, err := bip39.NewMnemonic(e)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%v\n", s)

	return nil
}
