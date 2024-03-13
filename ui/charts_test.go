// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package ui_test

import (
	"strings"
	"testing"

	"github.com/absmach/magistrala-ui/ui"
)

func TestCreateCharts(t *testing.T) {
	charts := ui.CreateCharts()
	if len(charts) == 0 {
		t.Errorf("Charts should not be empty")
	}
	for _, chart := range charts {
		if len(strings.Split(chart.Widget, " ")) != 1 {
			t.Errorf("Widget should not contain spaces")
		}
	}
}
