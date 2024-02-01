// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

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
			Title:   "Time Series Line Chart",
			Content: "This is simple cartesian axis time series line chart",
			Image:   "https://www.jqueryscript.net/images/Simple-Canvas-Based-Line-Chart-Plugin-For-jQuery-Topup.jpg",
			Widget:  "lineChart",
		},
		{
			Title:   "Time Series Bar Chart",
			Content: "This is simple cartesian axis time series bar chart",
			Image:   "https://sigma-docs-screenshots.s3.us-west-2.amazonaws.com/Workbooks/Visualizations/Build+a+Bar+Chart/bar-chart.png",
			Widget:  "barChart",
		},
		{
			Title:   "Simple Analogue Gauge",
			Content: "This is a radial analogue gauge",
			Image:   "https://www.infragistics.com/products/indigo-design/help/images/radial_gauge_inside-2@2x.png",
			Widget:  "gauge",
		},
		{
			Title:   "Pie Chart",
			Content: "This is a pie chart",
			Image:   "https://earthly.dev/blog/generated/assets/images/stop-using-pie-charts/pie-chart-800-a835136f5.png",
			Widget:  "pieChart",
		},
		{
			Title:   "Donut Chart",
			Content: "This is a donut chart",
			Image:   "https://media.geeksforgeeks.org/wp-content/uploads/20230322231450/Rplot07.png",
			Widget:  "donut",
		},
		{
			Title:   "Speed Gauge",
			Content: "This is an analogue speed gauge",
			Image:   "https://community-openhab-org.s3.dualstack.eu-central-1.amazonaws.com/original/3X/5/b/5b953b24910ffe51767d97af48d8d6c9125039a8.png",
			Widget:  "speedGauge",
		},
		{
			Title:   "Range Chart",
			Content: "This is a range chart",
			Image:   "https://storage.googleapis.com/studio_v_0_0_2/HVUMTI2S/_desktop_preview_1655159666002.png",
			Widget:  "stackedLineChart",
		},
		{
			Title:   "Area Line Chart",
			Content: "This is a stacked area line chart",
			Image:   "https://miro.medium.com/v2/resize:fit:657/1*q-EATOYjVUdgaFxnGlddpg.png",
			Widget:  "areaLineChart",
		},
		{
			Title:   "Temperature Gauge",
			Content: "This is an analogue temperature gauge",
			Image:   "https://screenshots.codesandbox.io/0s27xi/0.png",
			Widget:  "tempGauge",
		},
		{
			Title:   "Bar and Line Chart",
			Content: "This is a dynamic data bar and line chart",
			Image:   "https://i.stack.imgur.com/tYgjo.png",
			Widget:  "dynamicDataChart",
		},
		{
			Title:   "Horizontal Bar Chart",
			Content: "This is a horizontal bar chart",
			Image:   "https://datavizproject.com/wp-content/uploads/types/Bar-Chart-Horizontal.png",
			Widget:  "horizontalBarChart",
		},
	}

	return items
}
