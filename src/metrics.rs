use prometheus::{
    Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;

#[derive(Clone)]
pub struct Metrics {
    registry: Arc<Registry>,
    request_counter: IntCounterVec,
    error_counter: IntCounterVec,
    active_requests: IntGauge,
    request_duration: Histogram,
    token_usage: IntCounterVec,
}

impl Metrics {
    pub fn new() -> Result<Self> {
        let registry = Arc::new(Registry::new());

        let request_counter = IntCounterVec::new(
            Opts::new("model_requests_total", "Total number of model API requests"),
            &["provider", "model", "status"],
        )?;
        registry.register(Box::new(request_counter.clone()))?;

        let error_counter = IntCounterVec::new(
            Opts::new("model_errors_total", "Total number of model API errors"),
            &["provider", "model", "error_type"],
        )?;
        registry.register(Box::new(error_counter.clone()))?;

        let active_requests = IntGauge::new(
            Opts::new(
                "active_requests",
                "Number of currently active model API requests",
            ),
        )?;
        registry.register(Box::new(active_requests.clone()))?;

        let request_duration = Histogram::with_opts(HistogramOpts::new(
            "request_duration_seconds",
            "Model API request duration in seconds",
        ))?;
        registry.register(Box::new(request_duration.clone()))?;

        let token_usage = IntCounterVec::new(
            Opts::new("token_usage_total", "Total number of tokens used"),
            &["provider", "model", "type"],
        )?;
        registry.register(Box::new(token_usage.clone()))?;

        Ok(Self {
            registry,
            request_counter,
            error_counter,
            active_requests,
            request_duration,
            token_usage,
        })
    }

    pub fn record_request(&self, provider: &str, model: &str, status: &str) {
        self.request_counter
            .with_label_values(&[provider, model, status])
            .inc();
    }

    pub fn record_error(&self, provider: &str, model: &str, error_type: &str) {
        self.error_counter
            .with_label_values(&[provider, model, error_type])
            .inc();
    }

    pub fn record_token_usage(&self, provider: &str, model: &str, usage_type: &str, count: i64) {
        self.token_usage
            .with_label_values(&[provider, model, usage_type])
            .inc_by(count);
    }

    pub fn start_request(&self) -> RequestTimer {
        self.active_requests.inc();
        RequestTimer::new(self.clone())
    }

    pub fn collect_metrics(&self) -> String {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let mut buffer = Vec::new();
        encoder.encode(&self.registry.gather(), &mut buffer).unwrap_or_default();
        String::from_utf8(buffer).unwrap_or_default()
    }
}

pub struct RequestTimer {
    metrics: Metrics,
    timer: prometheus::HistogramTimer,
}

impl RequestTimer {
    fn new(metrics: Metrics) -> Self {
        Self {
            metrics: metrics.clone(),
            timer: metrics.request_duration.start_timer(),
        }
    }
}

impl Drop for RequestTimer {
    fn drop(&mut self) {
        self.timer.stop_and_record();
        self.metrics.active_requests.dec();
    }
}

#[derive(Clone)]
pub struct MetricsCollector {
    metrics: Arc<RwLock<Metrics>>,
}

impl MetricsCollector {
    pub fn new() -> Result<Self> {
        Ok(Self {
            metrics: Arc::new(RwLock::new(Metrics::new()?)),
        })
    }

    pub async fn record_request(&self, provider: &str, model: &str, status: &str) {
        let metrics = self.metrics.read().await;
        metrics.record_request(provider, model, status);
    }

    pub async fn record_error(&self, provider: &str, model: &str, error_type: &str) {
        let metrics = self.metrics.read().await;
        metrics.record_error(provider, model, error_type);
    }

    pub async fn record_token_usage(&self, provider: &str, model: &str, usage_type: &str, count: i64) {
        let metrics = self.metrics.read().await;
        metrics.record_token_usage(provider, model, usage_type, count);
    }

    pub async fn start_request(&self) -> RequestTimer {
        let metrics = self.metrics.read().await;
        metrics.start_request()
    }

    pub async fn collect_metrics(&self) -> String {
        let metrics = self.metrics.read().await;
        metrics.collect_metrics()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_metrics_recording() {
        let metrics = Metrics::new().unwrap();

        metrics.record_request("test_provider", "test_model", "success");
        metrics.record_error("test_provider", "test_model", "rate_limit");
        metrics.record_token_usage("test_provider", "test_model", "prompt", 100);

        let output = metrics.collect_metrics();
        assert!(output.contains("model_requests_total"));
        assert!(output.contains("model_errors_total"));
        assert!(output.contains("token_usage_total"));
    }

    #[tokio::test]
    async fn test_async_metrics_collector() {
        let collector = MetricsCollector::new().unwrap();

        collector
            .record_request("test_provider", "test_model", "success")
            .await;
        collector
            .record_error("test_provider", "test_model", "timeout")
            .await;

        let output = collector.collect_metrics().await;
        assert!(output.contains("test_provider"));
        assert!(output.contains("test_model"));
    }

    #[tokio::test]
    async fn test_request_timer() {
        let collector = MetricsCollector::new().unwrap();

        {
            let _timer = collector.start_request().await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let output = collector.collect_metrics().await;
        assert!(output.contains("request_duration_seconds"));
        assert!(output.contains("active_requests"));
    }
}