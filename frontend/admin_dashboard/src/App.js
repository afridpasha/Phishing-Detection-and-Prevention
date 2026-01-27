import React, { useState, useEffect } from 'react';
import { Box, AppBar, Toolbar, Typography, Container, Grid, Paper, Card, CardContent } from '@mui/material';
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import axios from 'axios';

const API_URL = 'http://localhost:8000/api/v1';

function App() {
  const [stats, setStats] = useState({ total_requests: 0, average_latency_ms: 0, decision_statistics: {} });
  const [recentDetections, setRecentDetections] = useState([]);

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchStats = async () => {
    try {
      const response = await axios.get(`${API_URL}/statistics`);
      setStats(response.data);
    } catch (error) {
      console.error('Failed to fetch stats:', error);
    }
  };

  const threatData = [
    { name: 'Blocked', value: stats.decision_statistics?.blocked || 0, color: '#f44336' },
    { name: 'Warned', value: stats.decision_statistics?.warned || 0, color: '#ff9800' },
    { name: 'Allowed', value: stats.decision_statistics?.allowed || 0, color: '#4caf50' }
  ];

  return (
    <Box sx={{ flexGrow: 1 }}>
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6">🛡️ Phishing Detection Dashboard</Typography>
        </Toolbar>
      </AppBar>
      
      <Container maxWidth="xl" sx={{ mt: 4 }}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>Total Requests</Typography>
                <Typography variant="h4">{stats.total_requests.toLocaleString()}</Typography>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>Avg Latency</Typography>
                <Typography variant="h4">{stats.average_latency_ms.toFixed(1)}ms</Typography>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>Threats Blocked</Typography>
                <Typography variant="h4" color="error">{stats.decision_statistics?.blocked || 0}</Typography>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2 }}>
              <Typography variant="h6" gutterBottom>Threat Distribution</Typography>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie data={threatData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label>
                    {threatData.map((entry, index) => <Cell key={index} fill={entry.color} />)}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </Paper>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2 }}>
              <Typography variant="h6" gutterBottom>Detection Performance</Typography>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={[
                  { name: 'NLP', accuracy: 0.92 },
                  { name: 'CNN', accuracy: 0.88 },
                  { name: 'GNN', accuracy: 0.85 },
                  { name: 'URL', accuracy: 0.95 }
                ]}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="accuracy" fill="#2196f3" />
                </BarChart>
              </ResponsiveContainer>
            </Paper>
          </Grid>
        </Grid>
      </Container>
    </Box>
  );
}

export default App;
