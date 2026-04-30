// Helper function to formulate pie chart
function renderEventTypeChart(labels, data) {
	const ctx = document.getElementById("eventTypeChart");

	if (!ctx) return;

	new Chart(ctx, {
		type: "pie",
		data: {
			labels: labels,
			datasets: [{
				data: data,
				backgroundColor: [
					"#ef4444",
					"#22c55e",
					"#3b82f6",
					"#f59e0b",
					"#a855f7",
					"#06b6d4",
					"#f97316",
					"#84cc16",
					"#ec4899",
					"#64748b"
				],
				borderColor: "#15161a",
				borderWidth: 2
			}]
		},
		options: {
			responsive: true,
			maintainAspectRation: false,
			plugins: {
				legend: {
					position: "right",
					labels: {
						color: "#f3f4f6",
						font: {
							size: 13,
							weight: "bold"
						},
						padding: 18
					}
				}
			}
		}
	});
}
