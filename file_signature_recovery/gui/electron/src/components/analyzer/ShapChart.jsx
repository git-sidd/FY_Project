import React, { useEffect, useRef } from 'react';
import Plotly from 'plotly.js-dist-min';
import { useTheme } from '../../context/ThemeContext.jsx';
import Card from '../ui/Card.jsx';

const ShapChart = ({ features }) => {
  const chartRef = useRef(null);
  const { theme } = useTheme();

  useEffect(() => {
    if (!chartRef.current || !features || features.length === 0) return;

    // Sort ascending so highest drops to the top of horizontal bar (Plotly draws bottom-up)
    const sorted = [...features].sort((a, b) => Math.abs(a.value) - Math.abs(b.value));
    
    const yData = sorted.map(f => f.feature);
    const xData = sorted.map(f => f.value);
    const markerColors = xData.map(v => v >= 0 ? '#6366f1' : '#ef4444'); // indigo / red

    const fontColor = theme === 'dark' ? '#9CA3AF' : '#4B5563'; // gray-400 : gray-600
    const gridColor = theme === 'dark' ? '#374151' : '#E5E7EB'; // gray-700 : gray-200

    const data = [
      {
        type: 'bar',
        x: xData,
        y: yData,
        orientation: 'h',
        marker: {
          color: markerColors
        }
      }
    ];

    const layout = {
      title: { 
        text: 'Feature importance \u2014 why this prediction?', 
        font: { size: 14, color: theme === 'dark' ? '#E5E7EB' : '#111827', family: 'sans-serif' }
      },
      margin: { l: 140, r: 20, t: 40, b: 20 },
      paper_bgcolor: 'rgba(0,0,0,0)',
      plot_bgcolor: 'rgba(0,0,0,0)',
      xaxis: {
        title: 'SHAP Value',
        gridcolor: gridColor,
        zerolinecolor: fontColor,
        tickfont: { color: fontColor },
        titlefont: { color: fontColor }
      },
      yaxis: {
        tickfont: { color: fontColor },
        automargin: true
      },
      height: 320,
      autosize: true
    };

    const config = { responsive: true, displayModeBar: false };

    Plotly.newPlot(chartRef.current, data, layout, config);

    return () => {
      Plotly.purge(chartRef.current);
    };
  }, [features, theme]);

  return (
    <Card className="w-full h-full p-2">
      <div ref={chartRef} className="w-full h-[320px]" />
    </Card>
  );
};

export default ShapChart;
