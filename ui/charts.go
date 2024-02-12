// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package ui

type Item struct {
	ID      int    `json:"id"`
	Title   string `json:"title"`
	Content string `json:"content"`
	Image   string `json:"image"`
	Widget  string `json:"widget"`
}

func CreateItem() []Item {
	items := []Item{
		{
			Title:   "Time Series Line Chart",
			Content: "This is simple cartesian axis time series line chart",
			Widget:  "lineChart",
		},
		{
			Title:   "Time Series Bar Chart",
			Content: "This is simple cartesian axis time series bar chart",
			Widget:  "barChart",
		},
		{
			Title:   "Simple Analogue Gauge",
			Content: "This is a radial analogue gauge",
			Widget:  "gauge",
		},
		{
			Title:   "Pie Chart",
			Content: "This is a pie chart",
			Widget:  "pieChart",
		},
		{
			Title:   "Donut Chart",
			Content: "This is a donut chart",
			Widget:  "donut",
		},
		{
			Title:   "Speed Gauge",
			Content: "This is an analogue speed gauge",
			Widget:  "speedGauge",
		},
		{
			Title:   "Range Chart",
			Content: "This is a range chart",
			Widget:  "stackedLineChart",
		},
		{
			Title:   "Area Line Chart",
			Content: "This is a stacked area line chart",
			Widget:  "areaLineChart",
		},
		{
			Title:   "Temperature Gauge",
			Content: "This is an analogue temperature gauge",
			Widget:  "tempGauge",
		},
		{
			Title:   "Bar and Line Chart",
			Content: "This is a dynamic data bar and line chart",
			Widget:  "dynamicDataChart",
		},
		{
			Title:   "Horizontal Bar Chart",
			Content: "This is a horizontal bar chart",
			Widget:  "horizontalBarChart",
		},
		{
			Title:   "Double Bar Chart",
			Content: "This is a double bar chart",
			Widget:  "doubleBarChart",
		},
		{
			Title:   "Multiple Line Chart",
			Content: "This is a multiple line chart",
			Widget:  "multipleLineChart",
		},
		{
			Title:   "Step Chart",
			Content: "This is a step chart",
			Widget:  "stepChart",
		},
		{
			Title:   "Multiple Gauge Chart",
			Content: "This is a multiple gauge chart",
			Widget:  "multiGauge",
		},
		{
			Title:   "Multiple Bar Chart",
			Content: "This is a multiple bar chart",
			Widget:  "multiBarChart",
		},
		{
			Title:   "Multiple Dataset Chart",
			Content: "This is a multiple dataset chart",
			Widget:  "sharedDataset",
		},
	}

	return items
}
