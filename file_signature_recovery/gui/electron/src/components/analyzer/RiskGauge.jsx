import React, { useEffect, useRef } from 'react';
import Plotly from 'plotly.js-dist-min';
import { useTheme } from '../../context/ThemeContext.jsx';
import Card from '../ui/Card.jsx';

const RiskGauge = ({ score }) => {
  const chartRef = useRef(null);
  const { theme } = useTheme();

  useEffect(() => {
    if (!chartRef.current) return;

    const fontColor = theme === 'dark' ? '#D1D5DB' : '#374151'; // gray-300 : gray-700
    
    const data = [
      {
        type: 'indicator',
        mode: 'gauge+number',
        value: score,
        title: { text: "Malware Risk Score", font: { size: 14, color: fontColor } },
        number: { font: { color: fontColor }, valueformat: ".3f" },
        gauge: {
          axis: { range: [0, 1], tickwidth: 1, tickcolor: fontColor },
          bar: { color: theme === 'dark' ? '#E5E7EB' : '#111827' },
          bgcolor: theme === 'dark' ? '#374151' : '#F3F4F6',
          borderwidth: 0,
          steps: [
            { range: [0, 0.3], color: theme === 'dark' ? '#064E3B' : '#D1FAE5' }, // Greenish
            { range: [0.3, 0.7], color: theme === 'dark' ? '#78350F' : '#FEF3C7' }, // Amberish
            { range: [0.7, 1.0], color: theme === 'dark' ? '#7F1D1D' : '#FEE2E2' }  // Reddish
          ],
        }
      }
    ];

    const layout = {
      width: 280,
      height: 200,
      margin: { t: 40, r: 25, l: 25, b: 25 },
      paper_bgcolor: 'rgba(0,0,0,0)',
      font: { color: fontColor, family: 'sans-serif' }
    };

    Plotly.newPlot(chartRef.current, data, layout, { staticPlot: true, responsive: true });

    return () => {
      Plotly.purge(chartRef.current);
    };
  }, [score, theme]);

  return (
    <Card className="flex flex-col items-center justify-center p-4">
      <div ref={chartRef} className="w-[280px] h-[200px]" />
    </Card>
  );
};

export default RiskGauge;
