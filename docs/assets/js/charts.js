// Chart.js configurations for RFC 9460 Adoption Tracker

// Chart defaults
Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif';
Chart.defaults.font.size = 12;

// Color palette
const colors = {
    primary: '#0d6efd',
    success: '#198754',
    warning: '#ffc107',
    info: '#0dcaf0',
    danger: '#dc3545',
    secondary: '#6c757d',
    light: '#f8f9fa',
    dark: '#212529'
};

// Initialize charts when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    initAdoptionChart();
    initFeaturesChart();
    // Timeline chart removed - only one data point available
    initAlpnChart();
    initPriorityChart();
});

// Overall Adoption Chart
function initAdoptionChart() {
    const ctx = document.getElementById('adoptionChart');
    if (!ctx) return;

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Has HTTPS Record', 'No HTTPS Record'],
            datasets: [{
                data: [18, 182],
                backgroundColor: [colors.success, colors.light],
                borderColor: [colors.success, '#dee2e6'],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 15,
                        font: {
                            size: 14
                        }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((context.parsed / total) * 100).toFixed(1);
                            return context.label + ': ' + context.parsed + ' (' + percentage + '%)';
                        }
                    }
                },
                datalabels: {
                    formatter: (value, ctx) => {
                        const sum = ctx.dataset.data.reduce((a, b) => a + b, 0);
                        const percentage = ((value / sum) * 100).toFixed(1) + '%';
                        return percentage;
                    },
                    color: '#fff',
                    font: {
                        weight: 'bold',
                        size: 16
                    }
                }
            }
        },
        plugins: [ChartDataLabels]
    });
}

// Features Distribution Chart
function initFeaturesChart() {
    const ctx = document.getElementById('featuresChart');
    if (!ctx) return;

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['HTTP/3', 'IPv4 Hints', 'IPv6 Hints', 'ECH Config'],
            datasets: [{
                label: 'Percentage of HTTPS-enabled domains',
                data: [72, 56, 33, 0],
                backgroundColor: [colors.info, colors.primary, colors.success, colors.secondary],
                borderColor: [colors.info, colors.primary, colors.success, colors.secondary],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    ticks: {
                        callback: function(value) {
                            return value + '%';
                        }
                    },
                    grid: {
                        borderDash: [5, 5]
                    }
                },
                x: {
                    grid: {
                        display: false
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return context.parsed.y + '% of HTTPS-enabled domains';
                        }
                    }
                }
            }
        }
    });
}

// Timeline chart removed - only one data point available
// Will be re-added when historical data is collected

// ALPN Protocol Distribution
function initAlpnChart() {
    const ctx = document.getElementById('alpnChart');
    if (!ctx) return;

    new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['h3 (HTTP/3)', 'h2 (HTTP/2)', 'No ALPN'],
            datasets: [{
                data: [13, 3, 2],
                backgroundColor: [colors.primary, colors.info, colors.light],
                borderColor: ['#fff', '#fff', '#fff'],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 15,
                        font: {
                            size: 14
                        }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((context.parsed / total) * 100).toFixed(1);
                            return context.label + ': ' + context.parsed + ' domains (' + percentage + '%)';
                        }
                    }
                }
            }
        }
    });
}

// Priority Values Chart
function initPriorityChart() {
    const ctx = document.getElementById('priorityChart');
    if (!ctx) return;

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Priority 1', 'Priority 2', 'Priority 3', 'Priority 4', 'Priority 5'],
            datasets: [{
                label: 'Number of domains',
                data: [18, 0, 0, 0, 0],
                backgroundColor: colors.warning,
                borderColor: colors.warning,
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 20,
                    ticks: {
                        stepSize: 5
                    },
                    title: {
                        display: true,
                        text: 'Number of Domains',
                        font: {
                            size: 14
                        }
                    },
                    grid: {
                        borderDash: [5, 5]
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'HTTPS Record Priority',
                        font: {
                            size: 14
                        }
                    },
                    grid: {
                        display: false
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return context.parsed.y + ' domains use ' + context.label.toLowerCase();
                        }
                    }
                }
            }
        }
    });
}
