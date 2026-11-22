// Command acp-evidence-verify verifies source-signed, same-Run lifecycle
// receipt consistency. It does not grant permissions or release resources.
package main

import (
    "bytes"
    "crypto/ed25519"
    "encoding/hex"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "strings"
    "time"

    "github.com/avaargsh/agent-control-panel/internal/evidencepackage"
)

const maxInput = 256 << 10

func readRegular(path string, limit int64) ([]byte, error) {
    before, err := os.Lstat(path)
    if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > limit {
        return nil, errors.New("file is missing, oversized or not regular")
    }
    f, err := os.Open(path)
    if err != nil { return nil, errors.New("unable to open required file") }
    defer f.Close()
    after, err := f.Stat()
    if err != nil || !after.Mode().IsRegular() || !os.SameFile(before,after) {
        return nil, errors.New("file changed or is unsafe")
    }
    raw, err := io.ReadAll(io.LimitReader(f, limit+1))
    if err != nil || len(raw) == 0 || int64(len(raw)) > limit {
        return nil, errors.New("invalid bounded file")
    }
    return raw, nil
}

func strictDecode(raw []byte, target any) bool {
    d := json.NewDecoder(bytes.NewReader(raw))
    d.DisallowUnknownFields()
    return d.Decode(target) == nil && d.Decode(new(any)) == io.EOF
}

func run(args []string) error {
    flags := flag.NewFlagSet("acp-evidence-verify", flag.ContinueOnError)
    flags.SetOutput(io.Discard)
    pkgPath := flags.String("package","","bounded signed evidence package")
    expectedPath := flags.String("expected","","independently sourced exact Run/fault/provider binding")
    trustDir := flags.String("trust-dir","","out-of-band service public keys")
    if err := flags.Parse(args); err != nil || flags.NArg()!=0 ||
        *pkgPath=="" || *expectedPath=="" || *trustDir=="" {
        return errors.New("--package, --expected and --trust-dir are mandatory")
    }
    rawPackage, err := readRegular(*pkgPath,maxInput)
    if err != nil { return errors.New("signed evidence package unavailable") }
    rawExpected, err := readRegular(*expectedPath,8192)
    if err != nil { return errors.New("independent expected binding unavailable") }
    var pkg evidencepackage.Package
    var expected evidencepackage.Expected
    if !strictDecode(rawPackage,&pkg) || !strictDecode(rawExpected,&expected) {
        return errors.New("invalid strict evidence JSON")
    }
    keys := make(map[string]ed25519.PublicKey)
    for _, authority := range []string{"acp","decision","guard","runtime","sandbox","agentd","compute"} {
        raw, err := readRegular(filepath.Join(*trustDir,authority+".pub"),128)
        if err != nil { return fmt.Errorf("missing %s trusted key",authority) }
        decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
        if err != nil || len(decoded) != ed25519.PublicKeySize {
            return fmt.Errorf("invalid %s trusted key",authority)
        }
        keys[authority] = ed25519.PublicKey(decoded)
    }
    return evidencepackage.Verify(pkg,expected,keys,time.Now().UTC())
}

func main() {
    if err := run(os.Args[1:]); err != nil {
        // Deliberately omit raw receipt payloads, tenant IDs and credentials.
        fmt.Fprintln(os.Stderr,"EVIDENCE PACKAGE BLOCKED:",err)
        os.Exit(1)
    }
    fmt.Println("EVIDENCE CONSISTENCY VERIFIED: signatures and same-Run links passed; real producer/physical release gates remain independent")
}
