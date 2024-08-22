package colasoft

import (
	"context"
	"errors"
	"go.opentelemetry.io/proto/otlp/profiles/v1experimental"
)

type (
	Writer interface {
		WriteProfile(context.Context, *v1experimental.Profile) error
	}

	multipleWriter struct {
		writers []Writer
	}
)

var _ Writer = (*multipleWriter)(nil)

func NewMultipleWriter(ws ...Writer) Writer { return &multipleWriter{writers: ws} }

func (m *multipleWriter) WriteProfile(ctx context.Context, p *v1experimental.Profile) error {
	errs := make([]error, len(m.writers))
	for idx, w := range m.writers {
		errs[idx] = w.WriteProfile(ctx, p)
	}
	return errors.Join(errs...)
}
