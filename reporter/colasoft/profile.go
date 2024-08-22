package colasoft

import (
	"github.com/google/uuid"
	"io"
)

type (
	ReadAtCloser interface {
		io.ReaderAt
		io.Closer
	}

	Opener func() (ReadAtCloser, error)

	Addr2liner interface {
		PrepareFile(string, string, Opener)
	}
)

var LabelFileIDKey = uuid.New().String()
