// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pkg/errors"
)

// Postgres error codes:
// https://www.postgresql.org/docs/current/errcodes-appendix.html
const (
	errDuplicate      = "23505" // unique_violation
	errTruncation     = "22001" // string_data_right_truncation
	errFK             = "23503" // foreign_key_violation
	errInvalid        = "22P02" // invalid_text_representation
	errUntranslatable = "22P05" // untranslatable_character
	errInvalidChar    = "22021" // character_not_in_repertoire
)

var (
	ErrConflict        = errors.New("entity already exists")
	ErrCreateEntity    = errors.New("failed to create entity in the db")
	ErrMalformedEntity = errors.New("malformed entity specification")
	ErrViewEntity      = errors.New("view entity failed")
	ErrNotFound        = errors.New("entity not found")
	ErrJSONMarshal     = errors.New("failed to marshal entity to json")
	ErrJSONUnmarshal   = errors.New("failed to unmarshal entity from json")
)

func HandleError(err, wrapper error) error {
	pqErr, ok := err.(*pgconn.PgError)
	if ok {
		switch pqErr.Code {
		case errDuplicate:
			return errors.Wrap(err, ErrConflict.Error())
		case errInvalid, errInvalidChar, errTruncation, errUntranslatable:
			return errors.Wrap(err, ErrMalformedEntity.Error())
		case errFK:
			return errors.Wrap(err, ErrCreateEntity.Error())
		}
	}

	return errors.Wrap(err, wrapper.Error())
}
