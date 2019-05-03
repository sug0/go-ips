package ips

import (
    "io"
    "bytes"
    "errors"
)

// Errors related with IPS patching.
var (
    // Failed to read the IPS magic string.
    ErrInvalidMagic = errors.New("ips: invalid IPS magic string")
)

// Represents an IPS data record reader.
type RecordReader struct {
    patch io.Reader
}

// Represents an IPS object capable of applying a patch to a file.
type Patcher struct {
    RecordReader
    file io.Reader
}

// Represents an IPS data record.
type Record struct {
    Offset int64
    Data   []byte
}

// An IPS patcher will take an IPS patch and a file, and produce a new patched file.
func NewPatcher(patch, file io.Reader) *Patcher {
    var p Patcher
    p.RecordReader.patch = patch
    p.file = file
    return &p
}

// Write the patched file into dstFile.
func (p *Patcher) PatchTo(dstFile io.WriteSeeker) (int64, error) {
    // copy data over...
    _, err := io.Copy(dstFile, p.file)
    if err != nil {
        return 0, err
    }

    // now start patching
    var wrote int64
    err = p.Records(true, func(rec Record) error {
        _, err := dstFile.Seek(rec.Offset, io.SeekStart)
        if err != nil {
            return err
        }
        n, err := dstFile.Write(rec.Data)
        if err != nil {
            return err
        }
        wrote += int64(n)
        return nil
    })

    if err != nil {
        return 0, err
    }
    return wrote, nil
}

// Constructs an IPS record reader object.
func NewRecordReader(patch io.Reader) *RecordReader {
    return &RecordReader{patch}
}

func (r *RecordReader) readFull(s []byte) error {
    _, err := io.ReadFull(r.patch, s)
    if err != nil {
        return err
    }
    return nil
}

func (r *RecordReader) checkHeader(s []byte) error {
    err := r.readFull(s)
    if err != nil {
        return err
    }
    if bytes.Equal(s, []byte("PATCH")) {
        return nil
    }
    return ErrInvalidMagic
}

// Takes a handler function that receives IPS records, and
// handles them in some way. This might be useful to implement
// custom IPS patchers.
//
// The first boolean argument allows the returned records to
// reuse the same slice, to be easier on the garbage collector.
func (r *RecordReader) Records(reuseDataSlice bool, handle func(Record) error) error {
    var buf [512]byte
    hdr := buf[:5]

    err := r.checkHeader(hdr)
    if err != nil {
        return err
    }

    var data []byte

    for {
        // read record header
        err = r.readFull(hdr[:3])
        if err != nil {
            return err
        }
        if bytes.Equal(hdr[:3], []byte("EOF")) {
            return nil
        }
        err = r.readFull(hdr[3:5])
        if err != nil {
            return err
        }

        off := bytes3ToInt64(hdr[:3])
        size := bytes2ToInt64(hdr[3:5])

        // RLE encoded
        if size == 0 {
            err = r.readFull(hdr[:3])
            size = bytes2ToInt64(hdr[:2])

            data = allocData(reuseDataSlice, data, size)
            repeat := hdr[2]

            for i := int64(0); i < size; i++ {
                data[i] = repeat
            }
        } else {
            data = allocData(reuseDataSlice, data, size)
            left := size

            for left != 0 {
                var n int
                if left > int64(len(buf)) {
                    n, err = r.patch.Read(buf[:])
                } else {
                    n, err = r.patch.Read(buf[:left])
                }
                if err != nil {
                    return err
                }
                copy(data[size-left:], buf[:n])
                left -= int64(n)
            }
        }

        // handle new record
        err = handle(Record{
            Offset: off,
            Data: data,
        })
        if err != nil {
            return err
        }
    }

    return nil
}

func allocData(reuse bool, data []byte, size int64) []byte {
    if reuse && int64(cap(data)) >= size {
        return data[:size]
    }
    return make([]byte, size)
}

func bytes3ToInt64(s []byte) int64 {
     return (int64(s[0]) << 16) | (int64(s[1]) << 8) | int64(s[2])
}

func bytes2ToInt64(s []byte) int64 {
    return (int64(s[0]) << 8) | int64(s[1])
}
