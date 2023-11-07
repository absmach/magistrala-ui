// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package encoder

import (
	"time"

	"github.com/mainflux/senml"
)

func EncodeSenML(bn, n, sv string) ([]byte, error) {
	ts := float64(time.Now().UnixNano()) / float64(time.Second)
	s := senml.Pack{
		Records: []senml.Record{
			{
				BaseName:    bn,
				Name:        n,
				Time:        ts,
				StringValue: &sv,
			},
		},
	}
	payload, err := senml.Encode(s, senml.JSON)
	if err != nil {
		return nil, err
	}
	return payload, nil
}
