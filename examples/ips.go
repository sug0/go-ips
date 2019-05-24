package main

import (
    "os"
    "flag"

    "github.com/sug0/go-ips"
)

func main() {
    var sfile, spatch, sdst string

    flag.StringVar(&sfile, "i", "", "The input file to patch.")
    flag.StringVar(&spatch, "p", "", "The IPS patch.")
    flag.StringVar(&sdst, "o", "", "The patched file to output.")
    flag.Parse()

    file, err := os.Open(sfile)
    if err != nil {
        panic(err)
    }
    defer file.Close()

    patch, err := os.Open(spatch)
    if err != nil {
        panic(err)
    }
    defer patch.Close()

    dst, err := os.Create(sdst)
    if err != nil {
        panic(err)
    }
    defer dst.Close()

    p := ips.NewPatcher(patch, file)
    _, err = p.PatchTo(dst)
    if err != nil {
        panic(err)
    }
}
