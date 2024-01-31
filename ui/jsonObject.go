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
			Title:   "Line Chart",
			Content: "This is a small sentence about a line chart",
			Image:   "https://example.com/image2.jpg",
			Widget:  "lineChart",
		},
		{
			Title:   "Gauge",
			Content: "This is a small sentence about a gauge",
			Image:   "https://example.com/image3.jpg",
			Widget:  "gauge",
		},
		{
			Title:   "Line Chart",
			Content: "This is a small sentence about a line chart",
			Image:   "https://example.com/image4.jpg",
			Widget:  "lineChart",
		},
		{
			Title:   "Line Chart",
			Content: "This is a small sentence about a line chart",
			Image:   "https://example.com/image5.jpg",
			Widget:  "lineChart",
		},
		{
			Title:   "Gauge",
			Content: "This is a small sentence about a gauge",
			Image:   "https://example.com/image6.jpg",
			Widget:  "gauge",
		},
		{
			Title:   "Line Chart",
			Content: "This is a small sentence about a line chart",
			Image:   "https://example.com/image7.jpg",
			Widget:  "lineChart",
		},
		{
			Title:   "Line Chart",
			Content: "This is a small sentence about a line chart",
			Image:   "https://example.com/image8.jpg",
			Widget:  "lineChart",
		},
		{
			Title:   "Gauge",
			Content: "This is a small sentence about a line chart",
			Image:   "https://example.com/image9.jpg",
			Widget:  "gauge",
		},
		{
			Title:   "Line Chart",
			Content: "This is a small sentence about a line chart",
			Image:   "https://example.com/image10.jpg",
			Widget:  "lineChart",
		},
	}

	return items
}
