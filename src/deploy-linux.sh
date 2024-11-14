curl -L https://api.github.com/repos/tom-gnade/prometheus-metrics-exporter/tarball/main | tar xz --wildcards --strip=2 "*/src"
sudo chown -R prometheus:prometheus /etc/prometheus/exporter
sudo chmod 755 /etc/prometheus/exporter
sudo chmod 644 /etc/prometheus/exporter/prometheus_metrics_exporter.yml
sudo chmod 755 /etc/prometheus/exporter/prometheus_metrics_exporter.py
rm -f *service *log
echo "Simple deploy complete"
venv/bin/python prometheus_metrics_exporter.py