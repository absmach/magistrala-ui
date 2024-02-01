// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

// To be Deleted. This is simulating the charts that we are going to get from the backend.
package ui

type Item struct {
	Id      int    `json:"id"`
	Title   string `json:"title"`
	Content string `json:"content"`
	Image   string `json:"image"`
	Widget  string `json:"widget"`
}

func CreateItem() []Item {
	items := []Item{
		{
			Title:   "Line Chart",
			Content: "This is a small sentence about a line chart",
			Image:   "https://example.com/image1.jpg",
			Widget:  "lineChart",
		},
		{
			Title:   "Time Series Bar Chart",
			Content: "This is a small sentence about a bar chart",
			Image:   "https://example.com/image2.jpg",
			Widget:  "barChart",
		},
		{
			Title:   "Simple Analogue Gauge",
			Content: "This is a small sentence about a gauge",
			Image:   "https://example.com/image3.jpg",
			Widget:  "gauge",
		},
		{
			Title:   "Pie Chart",
			Content: "This is a small sentence about a pie chart",
			Image:   "https://example.com/image4.jpg",
			Widget:  "pieChart",
		},
		{
			Title:   "Donut Chart",
			Content: "This is a small sentence about a line chart",
			Image:   "https://example.com/image5.jpg",
			Widget:  "donut",
		},
		{
			Title:   "Speed Gauge",
			Content: "This is a small sentence about a speed gauge",
			Image:   "https://example.com/image6.jpg",
			Widget:  "speedGauge",
		},
		{
			Title:   "Range Chart",
			Content: "This is a small sentence about a line chart",
			Image:   "https://example.com/image7.jpg",
			Widget:  "stackedLineChart",
		},
		{
			Title:   "Area Line Chart",
			Content: "This is a small sentence about a line chart",
			Image:   "https://example.com/image8.jpg",
			Widget:  "areaLineChart",
		},
		{
			Title:   "Temperature Gauge",
			Content: "This is a small sentence about a line chart",
			Image:   "https://example.com/image9.jpg",
			Widget:  "tempGauge",
		},
		{
			Title:   "Line Chart",
			Content: "This is a small sentence about a line chart",
			Image:   "https://example.com/image10.jpg",
			Widget:  "lineChart",
		},
		{
			Title:   "Horizontal Bar Chart",
			Content: "This is a small sentence about a bar chart",
			Image:   "https://example.com/image2.jpg",
			Widget:  "horizontalBarChart",
		},
	}

	return items
}
