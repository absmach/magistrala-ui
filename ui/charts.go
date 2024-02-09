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
			Title:   "Stacked Line Charts",
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
			Title:   "Dynamic Data Chart",
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
		{
			Title:   "Value Card",
			Content: "This is a text value card",
			Widget:  "valueCard",
		},
		{
			Title:   "Value and Chart Card",
			Content: "This is a value and chart card",
			Widget:  "valueChartCard",
		},
		{
			Title:   "Alarm Count Card",
			Content: "This is an alarm count card",
			Widget:  "alarmCount",
		},
		{
			Title:   "Alarms Table",
			Content: "This is an alarms table",
			Widget:  "alarmsTable",
		},
		{
			Title:   "Entities Table",
			Content: "This is an entities table",
			Widget:  "entitiesTable",
		},
		{
			Title:   "Entity Count Card",
			Content: "This is an entity count card",
			Widget:  "entityCount",
		},
		{
			Title:   "Label Card",
			Content: "This is a label card",
			Widget:  "label",
		},
		{
			Title:   "Progress Bar",
			Content: "This is a progress bar",
			Widget:  "progressBar",
		},
	}

	return items
}
