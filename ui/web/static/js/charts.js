// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

class Chart {
  constructor(widgetID, chartData) {
    this.ID = widgetID;
    this.chartData = chartData;
  }
}

class Echart extends Chart {
  constructor(widgetID, chartData) {
    super(widgetID, chartData);
    this.Style = {
      width: "400px",
      height: "400px",
    };
    this.Content = this.#generateContent();
  }
  #generateContent() {
    return `
      <div class="item-content" id="${this.ID}" style="width: ${this.Style.width}; height: ${this.Style.height};">
      </div>
      `;
  }
}
class AlarmCount extends Chart {
  constructor(chartData, widgetID) {
    super(widgetID, chartData);
    this.Style = {
      width: "400px",
      height: "175px",
    };
    this.Content = this.#generateContent();
  }

  #generateContent() {
    return `
    <div class="item-content" id="${this.ID}" style="width: ${this.Style.width}; height: ${this.Style.height};">
    <div class="card widgetcard">
        <div class="card-header text-center">
          <h5 class="card-title">Alarm Count</h5>
        </div>
        <div class="card-body text-center">
          <p class="card-text value"> 35</p>
        </div>
        <div class="card-footer text-center w-100 bg-warning">
          <p class="card-text">
            Warning Level
          </p>
        </div>
    </div>
    </div>
  `;
  }
}

class AlarmsTable extends Chart {
  constructor(chartData, widgetID) {
    super(widgetID, chartData);
    this.Style = {
      width: "400px",
      height: "200px",
    };
    this.Content = this.#generateContent();
  }

  #generateContent() {
    return `
    <div class="item-content" id="${this.ID}" style="width: ${this.Style.width}; height: ${this.Style.height};">
        <div class="card mt-3 widgetcard">
          <div class="card-header text-center">
            <h5 class="card-title">Alarms Table</h5>
          </div>
          <table class="table table-striped table-hover">
            <thead>
              <tr>
                <th scope="col">Severity</th>
                <th scope="col">Originator</th>
                <th scope="col">Status</th>
                <th scope="col">Time Started</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Warning</td>
                <td>Thing A</td>
                <td>Enabled</td>
                <td>2024-01-01 12:00</td>
              </tr>
              <tr>
                <td>Error</td>
                <td>Thing B</td>
                <td>Disabled</td>
                <td>2024-01-02 15:30</td>
              </tr>
            </tbody>
          </table>
        </div>
    </div>
      `;
  }
}

class AreaLineChart extends Echart {
  constructor(chartData, widgetID) {
    super(widgetID, chartData);
    this.Script = this.#generateScript();
  }

  #generateScript() {
    return `
    var areaLineChart = echarts.init(document.getElementById("${this.ID}"));
    var option = {
        tooltip: {
          trigger: 'axis',
          axisPointer: {
            type: 'cross',
            label: {
              backgroundColor: '#6a7985'
            }
          }
        },
        title: {
          text: '${this.chartData.title}',
        },
        legend: {
          data: ['voltage', 'current', 'temperature', 'pressue']
        },
        grid: {
          left: '3%',
          right: '4%',
          bottom: '3%',
          containLabel: true
        },
        xAxis: [
          {
            type: 'category',
            boundaryGap: false,
            data: ['thing1', 'thing2', 'thing3', 'thing4', 'thing5', 'thing6', 'thing7'],
            name: '${this.chartData.xAxisLabel}',
            nameLocation: 'middle',
            nameGap: 25,
          }
        ],
        yAxis: [
          {
            type: 'value',
            name: '${this.chartData.yAxisLabel}',
            nameLocation: 'middle',
            nameGap: 35,
          }
        ],
        series: [
          {
            name: 'voltage',
            type: 'line',
            stack: 'Total',
            areaStyle: {},
            emphasis: {
              focus: 'series'
            },
            data: [120, 132, 101, 134, 90, 230, 210]
          },
          {
            name: 'current',
            type: 'line',
            stack: 'Total',
            areaStyle: {},
            emphasis: {
              focus: 'series'
            },
            data: [220, 182, 191, 234, 290, 330, 310]
          },
          {
            name: 'temperature',
            type: 'line',
            stack: 'Total',
            areaStyle: {},
            emphasis: {
              focus: 'series'
            },
            data: [150, 232, 201, 154, 190, 330, 410]
          },
          {
            name: 'pressure',
            type: 'line',
            stack: 'Total',
            areaStyle: {},
            emphasis: {
              focus: 'series'
            },
            data: [320, 332, 301, 334, 390, 330, 320]
          },
        ]
      };

    areaLineChart.setOption(option);`;
  }
}

class TimeSeriesBarChart extends Echart {
  constructor(chartData, widgetID) {
    super(widgetID, chartData);
    this.Script = this.#generateScript();
  }

  #generateScript() {
    return `
    var barChart = echarts.init(document.getElementById("${this.ID}"));
    var option = {
      title: {
        text: '${this.chartData.title}',
        left: 'center',
        show: true
      },
      xAxis: {
        type: 'category',
        data: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
        name: '${this.chartData.xAxisLabel}',
        nameLocation: 'middle',
        nameGap: 35
      },
      yAxis: {
        type: 'value',
        name: '${this.chartData.yAxisLabel}',
        nameLocation: 'middle',
        nameGap: 35
      },
      legend: {
        show: true,
        left: 'right',
      },
        series: [
          {
            data: [120, 200, 150, 80, 70, 110, 130],
            type: 'bar',
            name: '${this.chartData.seriesName}'
          }
        ]
    };

    barChart.setOption(option);`;
  }
}

class DonutChart extends Echart {
  constructor(chartData, widgetID) {
    super(widgetID, chartData);
    this.Script = this.#generateScript();
  }

  #generateScript() {
    return `
    var donut = echarts.init(document.getElementById("${this.ID}"));
    var option = {
        title:{
          text:'${this.chartData.title}',
          left: 'center',
        },
        tooltip: {
          trigger: 'item'
        },
        legend: {
          top: '5%',
          left: 'center'
        },
        series: [
          {
            name: '${this.chartData.seriesName}',
            type: 'pie',
            radius: ['40%', '70%'],
            avoidLabelOverlap: false,
            label: {
              show: false,
              position: 'center'
            },
            emphasis: {
              label: {
                show: true,
                fontSize: 40,
                fontWeight: 'bold'
              }
            },
            labelLine: {
              show: false
            },
            data: [
              { value: 1048, name: 'Thing1' },
              { value: 735, name: 'Thing2' },
              { value: 580, name: 'Thing3' },
              { value: 484, name: 'Thing4' },
              { value: 300, name: 'Thing5' }
            ]
          }
        ]
    };

    donut.setOption(option);`;
  }
}

class DoubleBarChart extends Echart {
  constructor(chartData, widgetID) {
    super(widgetID, chartData);
    this.Script = this.#generateScript();
  }

  #generateScript() {
    let seriesName = this.chartData.seriesName.split(",");
    return `
    var doubleBarChart = echarts.init(document.getElementById("${this.ID}"));
    var option = {
      title: {
        text: '${this.chartData.title}',
        left: 'left'
      },
      tooltip: {
        trigger: 'axis'
      },
      legend: {
        show: true,

      },
      toolbox: {
        show: true,
        feature: {
          dataView: { show: true, readOnly: false },
          magicType: { show: true, type: ['line', 'bar'] },
          restore: { show: true },
          saveAsImage: { show: true }
        }
      },
      calculable: true,
      xAxis: [
        {
          type: 'category',
          // prettier-ignore
          data: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
          name: '${this.chartData.xAxisLabel}',
          nameLocation: 'middle',
          nameGap: 30
        }
      ],
      yAxis: [
        {
          type: 'value',
          name: '${this.chartData.yAxisLabel}',
          nameLocation: 'middle',
          nameGap: 40
        }
      ],
      series: [
        {
          name: '${seriesName[0]}',
          type: 'bar',
          data: [
            2.0, 4.9, 7.0, 23.2, 25.6, 76.7, 135.6, 162.2, 32.6, 20.0, 6.4, 3.3
          ],
          markPoint: {
            data: [
              { type: 'max', name: 'Max' },
              { type: 'min', name: 'Min' }
            ]
          },
          markLine: {
            data: [{ type: 'average', name: 'Avg' }]
          }
        },
        {
          name: '${seriesName[1]}',
          type: 'bar',
          data: [
            2.6, 5.9, 9.0, 26.4, 28.7, 70.7, 175.6, 182.2, 48.7, 18.8, 6.0, 2.3
          ],
          markPoint: {
            data: [
              { name: 'Max', value: 182.2, xAxis: 7, yAxis: 183 },
              { name: 'Min', value: 2.3, xAxis: 11, yAxis: 3 }
            ]
          },
          markLine: {
            data: [{ type: 'average', name: 'Avg' }]
          }
        }
      ]
    };

    doubleBarChart.setOption(option);
  `;
  }
}

class DynamicDataChart extends Echart {
  constructor(chartData, widgetID) {
    super(widgetID, chartData);
    this.Script = this.#generateScript();
  }

  #generateScript() {
    return `
    var dynamicDataChart = echarts.init(document.getElementById("${this.ID}"));
    var app = {};
    var categories = (function () {
        let now = new Date();
        let res = [];
        let len = 10;
        while (len--) {
            res.unshift(now.toLocaleTimeString().replace(/^\D*/, ''));
            now = new Date(+now - 2000);
        }
        return res;
    })();
    var categories2 = (function () {
        let res = [];
        let len = 10;
        while (len--) {
            res.push(10 - len - 1);
        }
        return res;
    })();
    var data = (function () {
        
        let res = [];
        let len = 10;
        while (len--) {
            res.push(Math.round(Math.random() * 1000));
        }
        return res;
    })();
    var data2 = (function () {
        let res = [];
        let len = 0;
        while (len < 10) {
            res.push(+(Math.random() * 10 + 5).toFixed(1));
            len++;
        }
        return res;
    })();
    var option = {
        title: {
            text: '${this.chartData.title}',
            left:'left'
        },
        tooltip: {
            trigger: 'axis',
            axisPointer: {
                    type: 'cross',
                label: {
                    backgroundColor: '#283b56'
                }
        }
        },
        legend: {},
        toolbox: {
            show: true,
        feature: {
            dataView: { readOnly: false },
            restore: {},
            saveAsImage: {}
        }
        },
        dataZoom: {
            show: false,
            start: 0,
            end: 100
        },
        xAxis: [
            {
                type: 'category',
                boundaryGap: true,
                data: categories,
                name: '${this.chartData.xAxisLabel}',
                nameLocation: 'middle',
                nameGap: 35
            },
            {
                type: 'category',
                boundaryGap: true,
                data: categories2
            }
        ],
        yAxis: [
            {
                type: 'value',
                scale: true,
                name: '${this.chartData.lineYAxisLabel}',
                nameLocation: 'middle',
                nameGap: '35',
                max: 30,
                min: 0,
                boundaryGap: [0.2, 0.2]
            },
            {
                type: 'value',
                scale: true,
                name: '${this.chartData.barYAxisLabel1}',
                nameLocation: 'middle',
                nameGap: '35',
                max: 1200,
                min: 0,
                boundaryGap: [0.2, 0.2]
            }
        ],
        series: [
            {
                name: '${this.chartData.barDataSeriesName}',
                type: 'bar',
                xAxisIndex: 1,
                yAxisIndex: 1,
                data: data
            },
            {
                name: '${this.chartData.lineDataSeriesName}',
                type: 'line',
                data: data2
            }
        ]
    };
    app.count = 11;
    setInterval(function () {
        let axisData = new Date().toLocaleTimeString().replace(/^\D*/, '');
        data.shift();
        data.push(Math.round(Math.random() * 1000));
        data2.shift();
        data2.push(+(Math.random() * 10 + 5).toFixed(1));
        categories.shift();
        categories.push(axisData);
        categories2.shift();
        categories2.push(app.count++);
        dynamicDataChart.setOption({
            xAxis: [
                {
                    data: categories
                },
                {
                    data: categories2
                }
            ],
            series: [
                {
                    data: data
                },
                {
                    data: data2
                }
            ]
        });
    }, 2100);

    dynamicDataChart.setOption(option);
  `;
  }
}

class EntitiesTable extends Chart {
  constructor(chartData, widgetID) {
    super(widgetID, chartData);
    this.Style = {
      width: "400px",
      height: "200px",
    };
    this.Content = this.#generateContent();
  }

  #generateContent() {
    return `
    <div class="item-content" id="${this.ID}" style="width: ${this.Style.width}; height: ${this.Style.height};">
  <div class="card mt-3 widgetcard">
    <div class="card-header text-center">
      <h5 class="card-title">Entities Table</h5>
    </div>
    <table class="table table-striped table-hover">
      <thead>
          <tr>
              <th scope="col">Name</th>
              <th scope="col">Owner</th>
              <th scope="col">Status</th>
              <th scope="col">Time Created</th>
          </tr>
      </thead>
      <tbody>
          <tr>
              <td>Entity 1</td>
              <td>Owner A</td>
              <td>Enabled</td>
              <td>2024-01-01 12:00</td>
          </tr>
          <tr>
              <td>Entity 2</td>
              <td>Owner B</td>
              <td>Disabled</td>
              <td>2024-01-02 15:30</td>
          </tr>
      </tbody>
    </table>
  </div>
  `;
  }
}

class EntityCount extends Chart {
  constructor(chartData, widgetID) {
    super(widgetID, chartData);
    this.Style = {
      width: "400px",
      height: "175px",
    };
    this.Content = this.#generateContent();
  }

  #generateContent() {
    return `
    <div class="item-content" id="${this.ID}" style="width: ${this.Style.width}; height: ${this.Style.height};">
        <div class="card widgetcard">
          <div class="card-header text-center">
            <h5 class="card-title">Entity Count</h5>
          </div>
          <div class="card-body text-center">
            <p class="card-text value"> 35</p>
          </div>
          <div class="card-footer text-right">
            <p class="card-text">
              Domain Name: D1
            </p>
          </div>
        </div>
    </div>
        `;
  }
}

class GaugeChart extends Echart {
  constructor(chartData, widgetID) {
    super(widgetID, chartData);
    this.Script = this.#generateScript();
  }

  #generateScript() {
    return `
  (function() {
    var gaugeChart = echarts.init(document.getElementById("${this.ID}"));
    var option = {
      title: {
        text: "${this.chartData.title}",
        left: "center",
      },
      tooltip: {
        formatter: "{a} <br/>{b} : {c}%",
      },
      series: [
        {
          type: "gauge",
          min: ${this.chartData.minValue},
          max: ${this.chartData.maxValue},
          progress: {
            show: true,
          },
          detail: { valueAnimation: true, formatter: "{value}" },
          data: [
            { 
              value: 50,
              name: "${this.chartData.gaugeLabel}",
             
            },
          ],
        },
      ],
    };

    gaugeChart.setOption(option);

    function updateGauge() {
        const randomValue = Math.floor(Math.random() * (${this.chartData.maxValue} - ${this.chartData.minValue} + 1)) + ${this.chartData.minValue};
        gaugeChart.setOption({
          series: [
            {
              data: [
                {
                  value: randomValue,
                  name: "${this.chartData.gaugeLabel}",
                },
              ],
            },
          ],
        });
    }
    setInterval(updateGauge, 2000);
  })();`;
  }
}

class HorizontalBarChart extends Echart {
  constructor(chartData, widgetID) {
    super(widgetID, chartData);
    this.Script = this.#generateScript();
  }

  #generateScript() {
    return `
      var horizontalBarChart = echarts.init(document.getElementById("${this.ID}"));
      var option = {
          title:{
            text: '${this.chartData.title}',
            left: 'center'
          },
          dataset: {
            source: [
              ['score', 'amount', 'product'],
              [79.3,85212, 'thing1'],
              [57.1, 78254, 'thing2'],
              [14.4, 41032, 'thing3'],
              [30.1, 12755, 'thing4'],
              [18.7, 20145, 'thing5'],
              [88.1, 89146, 'thing6'],
            ]
          },
          grid: { containLabel: true },
          xAxis: { 
            name: '${this.chartData.xAxisLabel}',
            nameLocation: 'middle',
            nameGap: 30,
            type: 'value',
          },
          yAxis: { 
            type: 'category',
            name: '${this.chartData.yAxisLabel}',
            nameLocation: 'middle',
            nameGap: 50,
          },
          visualMap: {
            orient: 'horizontal',
            left: 'center',
            min: 10,
            max: 100,
            text: ['High temperature', 'Low temperature'],
            // Map the score column to color
            dimension: 0,
            inRange: {
              color: ['#65B581', '#FFCE34', '#FD665F']
            }
          },
          series: [
            {
              type: 'bar',
              encode: {
                x: 'amount',
                y: 'product'
              }
            }
          ]
        };

      horizontalBarChart.setOption(option);`;
  }
}

class LabelCard extends Chart {
  constructor(chartData, widgetID) {
    super(widgetID, chartData);
    this.Style = {
      width: "420px",
      height: "180px",
    };
    this.Content = this.#generateContent();
  }

  #generateContent() {
    return `
    <div class="item-content" id="${this.ID}" style="width: ${this.Style.width}; height: ${this.Style.height};">
    <div class="card widgetcard">
    <div class="card-header text-center">
      <h5 class="card-title">Label</h5>
    </div>
    <div class="card-body text-center">
      <p class="card-subtitle mb-2 text-muted">Selected Entity: <span class="badge bg-primary">Thing6</span></p>
    </div>
    <div class="card-footer">
      <p class="card-text text"> ThingID: 666 666 666</p>
    </div>
    </div>
    </div>
`;
  }
}

class TimeSeriesLineChart extends Echart {
  constructor(chartData, widgetID) {
    super(widgetID, chartData);
    this.Script = this.#generateScript();
  }

  #generateScript() {
    const channels = JSON.stringify(this.chartData.channels);
    const things = JSON.stringify(this.chartData.things);
    const names = JSON.stringify(this.chartData.seriesNames);
    const colors = JSON.stringify(this.chartData.colors);
    return `
    var lineChart = echarts.init(document.getElementById("${this.ID}")); 
    var option = {
      title: {
        text: '${this.chartData.title}',
        left: 'center',
        show: true
      },
      tooltip: {
        trigger: 'axis',
      },
      xAxis: {
        type: 'category',
        name: '${this.chartData.xAxisLabel}',
        min: '${new Date(this.chartData.startTime)}',
        max: '${new Date(this.chartData.stopTime)}',
      },
      yAxis: {
        type: 'value',
        name: '${this.chartData.yAxisLabel}',
        nameLocation: 'middle',
      },
      legend: {
        show: true,
      },
      series: [
        {
          data: [],
          type: 'line',
          lineStyle: {
            width: ${this.chartData.lineWidth},
            type: 'solid',
          },
        }
      ]
    };

    lineChart.setOption(option);
    var chartdata = {
      channels:${channels},
      publishers:${things},
      names:${names},
      colors:${colors},
      valueName: '${this.chartData.valueName}',
      from:${this.chartData.startTime},
      to:${this.chartData.stopTime},
      aggregation:'${this.chartData.aggregationType}',
      limit:100,
      interval:'${this.chartData.updateInterval}',
    };
    getData(lineChart,chartdata);
  
    async function getData(linechart,chartData) {
      try {
        let xAxisArray=[];
        const yAxisArray = [];
        let currentTimestamp = chartData.from;
        let previousTimestamp=0;
        const endTimestamp = chartData.to;
        const timeDifference = chartData.to - chartData.from;
        let intervalNum;
        switch (true) {
          case (timeDifference <= 3.6*1e6):
            intervalNum = 6*1e5;
            break;
          case (timeDifference <= 8.64 * 1e7):
            intervalNum = 6*1e6;
            break;
          case (timeDifference <= 6.05 * 1e8):
            intervalNum = 6*1e7;
            break;
          case (timeDifference <= 2.63 * 1e9):
            intervalNum = 6*1e8;
            break;
          case (timeDifference <= 3.16 * 1e10):
            intervalNum = 6*1e9;
            break;
          default:
            intervalNum = 6*1e8;
            break;
        }

        const initialXAxisArray = []
        const NoOfValues = Math.ceil(timeDifference/intervalNum);
        for (i=0; i<=NoOfValues; i++) {
          initialXAxisArray.push(currentTimestamp);
          currentTimestamp += intervalNum;
        }
        xAxisArray.push(initialXAxisArray);

        for (i=0; i < chartData.channels.length; i++) {
          const url = "${pathPrefix}/data?channel=" + chartData.channels[i] +
          "&publisher=" + chartData.publishers[i] +
          "&name=" + chartData.valueName +
          "&from=" + chartData.from +
          "&to=" + chartData.to +
          "&aggregation=" + chartData.aggregation +
          "&limit=" + chartData.limit +
          "&interval=" + chartData.interval;
          const response = await fetch(url);
          if (response.ok) {
            const data = await response.json();
            const xAxis=[];
            const yAxis=[];
            if (data.messages){
              const currArray = xAxisArray[xAxisArray.length-1];
              let currentTime, previousTime;
              for (j=0; j < currArray.length; j++) {
                let isempty = true;
                let currentTime = currArray[j];
                for (k = (data.messages.length -1); k>= 0 ; k--) {
                  const item = data.messages[k];
                  if (item.time > previousTime && item.time <= currentTime ) {
                    xAxis.push(item.time);
                    yAxis.push(item.value);
                    isEmpty= false;
                  }
                }
                if (isempty) {
                  xAxis.push(currentTime);
                  yAxis.push("-");
                }
                previousTime=currentTime;
              }
            }
            xAxisArray.push(xAxis);
            yAxisArray.push(yAxis);
          } else {
            // Handle errors
            console.error("HTTP request failed with status:", response.status);
          }
        }

        for (i =1; i< xAxisArray.length; i++) {
          const missingData = findMissingValuesIndices(xAxisArray[i], xAxisArray[xAxisArray.length-1]);
          missingData.forEach((value, index) => {
            yAxisArray[i-1].splice(value,0,"-");
          });
        }

        function findMissingValuesIndices(array1, array2) {
          const missingIndices = [];
          array2.forEach((item, index) => {
              if (!array1.includes(item)) {
                  missingIndices.push(index);
              }
          });
          return missingIndices;
        }
        
        const xAxisData=[];
        xAxisArray[xAxisArray.length-1].forEach((element) => {
          const date = new Date(element);
          xAxisData.push(date);
        })
        const seriesData = []
        for (i=0; i<yAxisArray.length; i++) {
          const data = {
            data: yAxisArray[i],
            type: 'line',
            lineStyle: {
              color: chartData.colors[i],
            },
            name: chartData.names[i],
          };
          seriesData.push(data);
        }
        linechart.setOption({
            xAxis: {
              data: xAxisData,
            },
            series: seriesData,
          });

      } catch (error) {
          // Handle fetch or other errors
          console.error("Error:", error);
          // Retry after a couple of seconds
          setTimeout(function () {
            getData(linechart, chartData);
          }, 20000);
        }
      };
    `;
  }
}

class MultiBarChart extends Echart {
  constructor(chartData, widgetID) {
    super(widgetID, chartData);
    this.Script = this.#generateScript();
  }

  #generateScript() {
    let seriesName = this.chartData.seriesName.split(",");
    return `
    var multiBarChart = echarts.init(document.getElementById("${this.ID}"));
    var app = {}
    var posList = [
        'left',
        'right',
        'top',
        'bottom',
        'inside',
        'insideTop',
        'insideLeft',
        'insideRight',
        'insideBottom',
        'insideTopLeft',
        'insideTopRight',
        'insideBottomLeft',
        'insideBottomRight'
    ];
    app.configParameters = {
            rotate: {
            min: -90,
            max: 90
        },
        align: {
        options: {
            left: 'left',
            center: 'center',
            right: 'right'
        }
        },
        verticalAlign: {
        options: {
            top: 'top',
            middle: 'middle',
            bottom: 'bottom'
        }
        },
        position: {
        options: posList.reduce(function (map, pos) {
            map[pos] = pos;
            return map;
        }, {})
        },
        distance: {
        min: 0,
        max: 100
        }
    };
    app.config = {
        rotate: 90,
        align: 'left',
        verticalAlign: 'middle',
        position: 'insideBottom',
        distance: 15,
        onChange: function () {
        const labelOption = {
            rotate: app.config.rotate,
            align: app.config.align,
            verticalAlign: app.config.verticalAlign,
            position: app.config.position,
            distance: app.config.distance
        };
        multiBarChart.setOption({
            series: [
            {
                label: labelOption
            },
            {
                label: labelOption
            },
            {
                label: labelOption
            },
            {
                label: labelOption
            }
            ]
        });
        }
    };
    var labelOption = {
        show: true,
        position: app.config.position,
        distance: app.config.distance,
        align: app.config.align,
        verticalAlign: app.config.verticalAlign,
        rotate: app.config.rotate,
        formatter: '{c}  {name|{a}}',
        fontSize: 16,
        rich: {
        name: {}
        }
    };
    var option = {
        title: {
          text: '${this.chartData.title}',
          left: 'left'
        },
        tooltip: {
        trigger: 'axis',
        axisPointer: {
            type: 'shadow'
        }
        },
        legend: {
          show: true,
          left: 'right',
        },
        toolbox: {
        show: true,
        orient: 'vertical',
        left: 'right',
        top: 'center',
        feature: {
            mark: { show: true },
            dataView: { show: true, readOnly: false },
            magicType: { show: true, type: ['line', 'bar', 'stack'] },
            restore: { show: true },
            saveAsImage: { show: true }
        }
        },
        xAxis: [
        {
            type: 'category',
            axisTick: { show: false },
            data: ['2012', '2013', '2014', '2015', '2016'],
            name: '${this.chartData.xAxisLabel}',
            nameLocation: 'middle',
            nameGap: 30
        }
        ],
        yAxis: [
        {
            type: 'value',
            name: '${this.chartData.yAxisLabel}',
            nameLocation: 'middle',
            nameGap: 40
        }
        ],
        series: [
        {
            name: '${seriesName[0]}',
            type: 'bar',
            barGap: 0,
            label: labelOption,
            emphasis: {
            focus: 'series'
            },
            data: [320, 332, 301, 334, 390]
        },
        {
            name: '${seriesName[1]}',
            type: 'bar',
            label: labelOption,
            emphasis: {
            focus: 'series'
            },
            data: [220, 182, 191, 234, 290]
        },
        {
            name: '${seriesName[2]}',
            type: 'bar',
            label: labelOption,
            emphasis: {
            focus: 'series'
            },
            data: [150, 232, 201, 154, 190]
        },
        {
            name: '${seriesName[3]}',
            type: 'bar',
            label: labelOption,
            emphasis: {
            focus: 'series'
            },
            data: [98, 77, 101, 99, 40]
        }
        ]
    };
    multiBarChart.setOption(option);
  `;
  }
}

class MultiGaugeChart extends Echart {
  constructor(chartData, widgetID) {
    super(widgetID, chartData);
    this.Script = this.#generateScript();
  }

  #generateScript() {
    let gaugeLabel = this.chartData.gaugeLabel.split(",");
    return `
    var multiGaugeChart = echarts.init(document.getElementById("${this.ID}"));
    var gaugeData = [
    {
      value: 20,
      name: '${gaugeLabel[0]}',
      title: {
        offsetCenter: ['0%', '-30%']
      },
      detail: {
        valueAnimation: true,
        offsetCenter: ['0%', '-18%']
      }
    },
    {
      value: 40,
      name: '${gaugeLabel[1]}',
      title: {
        offsetCenter: ['0%', '0%']
      },
      detail: {
        valueAnimation: true,
        offsetCenter: ['0%', '12%']
      }
    },
    {
      value: 60,
      name: '${gaugeLabel[2]}',
      title: {
        offsetCenter: ['0%', '28%']
      },
      detail: {
        valueAnimation: true,
        offsetCenter: ['0%', '40%']
      }
    }
  ];
  var option = {
    title: {
      text: '${this.chartData.title}',
      left: 'center'
    },
    series: [
      {
        type: "gauge",
        min: ${this.chartData.minValue},
        max: ${this.chartData.maxValue},
        pointer: {
          show: false
        },
        progress: {
          show: true,
          overlap: false,
          roundCap: true,
          clip: false,
          itemStyle: {
            borderWidth: 1,
            borderColor: '#464646'
          }
        },
        axisLine: {
          lineStyle: {
            width: 30
          }
        },
        splitLine: {
          show: false,
          distance: 0,
          length: 10
        },
        axisTick: {
          show: false
        },
        axisLabel: {
          show: false,
          distance: 50
        },
        data: gaugeData,
        title: {
          fontSize: 10
        },
        detail: {
          width: 50,
          height: 14,
          fontSize: 14,
          color: 'inherit',
          borderColor: 'inherit',
          borderRadius: 20,
          borderWidth: 1,
          formatter: '{value}%'
        }
      }
    ]
  };
  multiGaugeChart.setOption(option);
  `;
  }
}

class PieChart extends Echart {
  constructor(chartData, widgetID) {
    super(widgetID, chartData);
    this.Script = this.#generateScript();
  }

  #generateScript() {
    return `
    var pieChart = echarts.init(document.getElementById("${this.ID}"));
    var option = {
        title: {
            text: '${this.chartData.title}',
            left: 'center',
        },
        tooltip: {
            trigger: 'item'
        },
        legend: {
            orient: 'vertical',
            left: 'left'
        },
        series: [
            {
            name: '${this.chartData.seriesName}',
            type: 'pie',
            radius: '50%',
            data: [
                { value: 1048, name: 'thing1' },
                { value: 735, name: 'thing2' },
                { value: 580, name: 'thing3' },
                { value: 484, name: 'thing4' },
                { value: 300, name: 'thing5' }
            ],
            emphasis: {
                itemStyle: {
                shadowBlur: 10,
                shadowOffsetX: 0,
                shadowColor: 'rgba(0, 0, 0, 0.5)'
                }
            }
            }
        ]
    };

    pieChart.setOption(option);`;
  }
}

class ProgressBar extends Chart {
  constructor(chartData, widgetID) {
    super(widgetID, chartData);
    this.Style = {
      width: "400px",
      height: "100px",
    };
    this.Content = this.#generateContent();
  }

  #generateContent() {
    return `
    <div class="item-content" id="${this.ID}" style="width: ${this.Style.width}; height: ${this.Style.height};">
        <div class="card widgetcard">
          <div class="card-header text-center">
            <h5 class="card-title">${this.chartData.title}</h5>
          </div>
          <div class="card-body p-2">
            <div class="progress">
              <div class="progress-bar ${this.chartData.progressBarColor}" role="progressbar" style="width: 70%" aria-valuemin=${this.chartData.minValue} 
              aria-valuemax=${this.chartData.maxValue}></div>
            </div>
          </div>
          <div class="card-footer text-center">
            <p class="card-text">
              Status: 70%
            </p>
          </div>
        </div>
    </div>
      `;
  }
}

class SharedDatasetChart extends Echart {
  constructor(chartData, widgetID) {
    super(widgetID, chartData);
    this.Script = this.#generateScript();
  }

  #generateScript() {
    let seriesName = this.chartData.seriesName.split(",");
    return `
    var sharedDataset = echarts.init(document.getElementById("${this.ID}"));
    var option = {
      title: {
        text: '${this.chartData.title}',
        left: 'left'
      },
      legend: {
        show: true,
        left: 'right',
      },
      tooltip: {
        trigger: 'axis',
        showContent: false
      },
      dataset: {
        source: [
          ['product', '2012', '2013', '2014', '2015', '2016', '2017'],
          ['Things', 56.5, 82.1, 88.7, 70.1, 53.4, 85.1],
          ['Users', 51.1, 51.4, 55.1, 53.3, 73.8, 68.7],
          ['Channels', 40.1, 62.2, 69.5, 36.4, 45.2, 32.5],
          ['Groups', 25.2, 37.1, 41.2, 18, 33.9, 49.1]
        ]
      },
      xAxis: {
        type: 'category',
        name:'${this.chartData.xAxisLabel}',
        nameLocation: 'middle',
        nameGap: 30
      },
      yAxis: {
        gridIndex: 0,
        name: '${this.chartData.yAxisLabel}',
        nameLocation: 'middle',
        nameGap: 40
      },
      grid: { top: '55%' },
      series: [
        {
          type: 'line',
          smooth: true,
          seriesLayoutBy: 'row',
          emphasis: { focus: 'series' },
          name: '${seriesName[0]}'
        },
        {
          type: 'line',
          smooth: true,
          seriesLayoutBy: 'row',
          emphasis: { focus: 'series' },
          name: '${seriesName[1]}'
        },
        {
          type: 'line',
          smooth: true,
          seriesLayoutBy: 'row',
          emphasis: { focus: 'series' },
          name: '${seriesName[2]}'
        },
        {
          type: 'line',
          smooth: true,
          seriesLayoutBy: 'row',
          emphasis: { focus: 'series' },
          name: '${seriesName[3]}'
        },
        {
          type: 'pie',
          id: 'pie',
          radius: '30%',
          center: ['50%', '25%'],
          emphasis: {
            focus: 'self'
          },
          label: {
            formatter: '{b}: {@2012} ({d}%)'
          },
          encode: {
            itemName: 'product',
            value: '2012',
            tooltip: '2012'
          }
        }
      ]
    };
    sharedDataset.on('updateAxisPointer', function (event) {
      const xAxisInfo = event.axesInfo[0];
      if (xAxisInfo) {
        const dimension = xAxisInfo.value + 1;
        sharedDataset.setOption({
          series: {
            id: 'pie',
            label: {
              formatter: '{b}: {@[' + dimension + ']} ({d}%)'
            },
            encode: {
              value: dimension,
              tooltip: dimension
            }
          }
        });
      }
    });
    sharedDataset.setOption(option);
  `;
  }
}

class SpeedGaugeChart extends Echart {
  constructor(chartData, widgetID) {
    super(widgetID, chartData);
    this.Script = this.#generateScript();
  }

  #generateScript() {
    return `
    var speedGaugeChart = echarts.init(document.getElementById("${this.ID}"));
    var option = {
        title: {
          text: '${this.chartData.title}',
          left: 'center',
          top: 20,
          show: true,
        },
        series: [
          {
            type: 'gauge',
            axisLine: {
              lineStyle: {
                width: 30,
                color: [
                  [0.3, '#67e0e3'],
                  [0.7, '#37a2da'],
                  [1, '#fd666d']
                ]
              }
            },
            pointer: {
              itemStyle: {
                color: 'auto'
              }
            },
            axisTick: {
              distance: -30,
              length: 8,
              lineStyle: {
                color: '#fff',
                width: 2
              }
            },
            splitLine: {
              distance: -30,
              length: 30,
              lineStyle: {
                color: '#fff',
                width: 4
              }
            },
            axisLabel: {
              color: 'inherit',
              distance: 40,
              fontSize: 20
            },
            detail: {
              valueAnimation: true,
              formatter: '{value} km/h',
              color: 'inherit'
            },
            data: [
              {
                value: 25,
                name: "${this.chartData.gaugeLabel}",
              }
            ]
          }
        ]
      };
      setInterval(function () {
        speedGaugeChart.setOption({
          series: [
            {
              data: [
                {
                  value: +(Math.random() * 100).toFixed(2),
                  name: "${this.chartData.gaugeLabel}",
                }
              ]
            }
          ]
        });
      }, 2000);

    speedGaugeChart.setOption(option);`;
  }
}

class StackedLineChart extends Echart {
  constructor(chartData, widgetID) {
    super(widgetID, chartData);
    this.Script = this.#generateScript();
  }

  #generateScript() {
    let seriesName = this.chartData.seriesName.split(",");
    return `
    var stackedLineChart = echarts.init(document.getElementById("${this.ID}"));
    var option = {
        title: {
          text: "${this.chartData.title}",
          left: 'left',
        },
        tooltip: {
          trigger: 'axis'
        },
        legend: {
          data: ['${seriesName[0]}', '${seriesName[1]}', '${seriesName[2]}'],
          left: 'right',
        },
        grid: {
          left: '3%',
          right: '4%',
          bottom: '3%',
          containLabel: true
        },
        toolbox: {
          feature: {
            saveAsImage: {}
          }
        },
        xAxis: {
          type: 'category',
          boundaryGap: false,
          data: ['Thing1', 'Thing2', 'Thing3', 'Thing4', 'Thing5', 'Thing6', 'Thing7'],
          name: '${this.chartData.xAxisLabel}',
          nameLocation: 'middle',
          nameGap: 35,
        },
        yAxis: {
          type: 'value',
          name: '${this.chartData.yAxisLabel}',
          nameLocation: 'middle',
          nameGap: 35,
        },
        series: [
          {
            name: '${seriesName[0]}',
            type: 'line',
            stack: 'Total',
            data: [120, 132, 101, 134, 90, 230, 210]
          },
          {
            name: '${seriesName[1]}',
            type: 'line',
            stack: 'Total',
            data: [220, 182, 191, 234, 290, 330, 310]
          },
          {
            name: '${seriesName[2]}',
            type: 'line',
            stack: 'Total',
            data: [150, 232, 201, 154, 190, 330, 410]
          },
        ]
      };

    stackedLineChart.setOption(option);`;
  }
}

class StepChart extends Echart {
  constructor(chartData, widgetID) {
    super(widgetID, chartData);
    this.Script = this.#generateScript();
  }

  #generateScript() {
    let seriesName = this.chartData.seriesName.split(",");
    return `
    var stepChart = echarts.init(document.getElementById("${this.ID}"));
    var option = {
      title: {
        text: '${this.chartData.title}',
        left: 'left'
      },
      tooltip: {
        trigger: 'axis'
      },
      legend: {
        show: true,
        left: 'right',
      },
      grid: {
        left: '3%',
        right: '4%',
        bottom: '3%',
        containLabel: true
      },
      toolbox: {
        feature: {
          saveAsImage: {}
        }
      },
      xAxis: {
        type: 'category',
        data: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
        name: '${this.chartData.xAxisLabel}',
        nameLocation: 'middle',
        nameGap: 30
      },
      yAxis: {
        type: 'value',
        name: '${this.chartData.yAxisLabel}',
        nameLocation: 'middle',
        nameGap: 40
      },
      series: [
        {
          name: '${seriesName[0]}',
          type: 'line',
          step: 'start',
          data: [120, 132, 101, 134, 90, 230, 210]
        },
        {
          name: '${seriesName[1]}',
          type: 'line',
          step: 'middle',
          data: [220, 282, 201, 234, 290, 430, 410]
        },
        {
          name: '${seriesName[2]}',
          type: 'line',
          step: 'end',
          data: [450, 432, 401, 454, 590, 530, 510]
        }
      ]
    };
    stepChart.setOption(option);`;
  }
}

class TempGaugeChart extends Echart {
  constructor(chartData, widgetID) {
    super(widgetID, chartData);
    this.Script = this.#generateScript();
  }

  #generateScript() {
    return `
    var tempGaugeChart = echarts.init(document.getElementById("${this.ID}"));
    var option = {
        title: {
          text: '${this.chartData.title}',
          left: 'center',
          textStyle: {
            color: '#FFAB91'
          }
        },
        series: [
          {
            type: 'gauge',
            center: ['50%', '80%'],
            startAngle: 200,
            endAngle: -20,
            min: 0,
            max: 60,
            splitNumber: 12,
            itemStyle: {
              color: '#FFAB91'
            },
            progress: {
              show: true,
              width: 30
            },
            pointer: {
              show: false
            },
            axisLine: {
              lineStyle: {
                width: 30
              }
            },
            axisTick: {
              distance: -44,
              splitNumber: 5,
              lineStyle: {
                width: 2,
                color: '#999'
              }
            },
            splitLine: {
              distance: -52,
              length: 7,
              lineStyle: {
                width: 2,
                color: '#999'
              }
            },
            axisLabel: {
              distance: -20,
              color: '#999',
              fontSize: 20
            },
            anchor: {
              show: false
            },
            title: {
              show: false
            },
            detail: {
              valueAnimation: true,
              width: '60%',
              lineHeight: 40,
              borderRadius: 1,
              offsetCenter: [0, '-5%'],
              fontSize: 30,
              fontWeight: 'bolder',
              formatter: '{value} °C',
              color: 'inherit'
            },
            data: [
              {
                value: 20
              }
            ]
          },
          {
            type: 'gauge',
            center: ['50%', '80%'],
            startAngle: 200,
            endAngle: -20,
            min: 0,
            max: 60,
            itemStyle: {
              color: '#FD7347'
            },
            progress: {
              show: true,
              width: 8
            },
            pointer: {
              show: false
            },
            axisLine: {
              show: false
            },
            axisTick: {
              show: false
            },
            splitLine: {
              show: false
            },
            axisLabel: {
              show: false
            },
            detail: {
              show: false
            },
            data: [
              {
                value: 37,
                name: '${this.chartData.gaugeLabel}'
              }
            ]
          }
        ]
      };
      setInterval(function () {
        const random = +(Math.random() * 60).toFixed(2);
        tempGaugeChart.setOption({
          series: [
            {
              data: [
                {
                  value: random
                }
              ]
            },
            {
              data: [
                {
                  value: random,
                  name: '${this.chartData.gaugeLabel}'
                }
              ]
            }
          ]
        });
      }, 2000);

    tempGaugeChart.setOption(option);`;
  }
}

class ValueCard extends Chart {
  constructor(chartData, widgetID) {
    super(widgetID, chartData);
    this.Style = {
      width: "400px",
      height: "200px",
    };
    this.Content = this.#generateContent();
  }

  #generateContent() {
    return `
    <div class="item-content" id="${this.ID}" style="width: ${this.Style.width}; height: ${this.Style.height};">
    <div class="card mt-3 widgetcard" >
      <div class="card-header text-center">
        <h5 class="card-title">${this.chartData.title}</h5>
      </div>
      <div class="card-body text-center">
        <p class="card-text value"> 35</p>
      </div>
      <div class="card-footer">
        <p class="card-text"> Units: ${this.chartData.valueUnits}</p>
        <p class="card-text text"> ThingName: ${this.chartData.thingName}</p>
      </div>
    </div>
    </div>
  `;
  }
}

const chartTypes = {
  alarmCount: AlarmCount,
  alarmsTable: AlarmsTable,
  areaLineChart: AreaLineChart,
  timeSeriesBarChart: TimeSeriesBarChart,
  donutChart: DonutChart,
  doubleBarChart: DoubleBarChart,
  dynamicDataChart: DynamicDataChart,
  entitiesTable: EntitiesTable,
  entityCount: EntityCount,
  gaugeChart: GaugeChart,
  horizontalBarChart: HorizontalBarChart,
  labelCard: LabelCard,
  lineChart: TimeSeriesLineChart,
  multiBarChart: MultiBarChart,
  multiGaugeChart: MultiGaugeChart,
  pieChart: PieChart,
  progressBar: ProgressBar,
  sharedDatasetChart: SharedDatasetChart,
  speedGaugeChart: SpeedGaugeChart,
  stackedLineChart: StackedLineChart,
  stepChart: StepChart,
  tempGaugeChart: TempGaugeChart,
  valueCard: ValueCard,
};

class Widget {
  constructor(chartData, widgetID) {
    this.chartData = chartData;
    this.widgetID = widgetID;
    this.config = new chartTypes[this.chartData.Type](chartData, widgetID);
    this.element = this.#createWidgetElement();
  }

  #createWidgetElement() {
    const newItem = document.createElement("div");
    newItem.className = "item item-editable";
    newItem.innerHTML = `
        <div class="item-border">
          <button type="button" class="btn btn-sm" id="removeItem" onclick="removeGridItem(this.parentNode.parentNode);">
            <i class="fas fa-trash-can"></i>
          </button>
          ${this.config.Content}
          </div>
        `;
    if (this.config.Script) {
      let scriptTag = document.createElement("script");
      scriptTag.type = "text/javascript";
      scriptTag.defer = true;
      scriptTag.innerHTML = this.config.Script;
      newItem.appendChild(scriptTag);
    }
    Object.assign(newItem.style, {
      minWidth: this.config.Style.width,
      minHeight: this.config.Style.height,
    });
    return newItem;
  }
}
