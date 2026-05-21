use std::{collections::HashMap, sync::LazyLock, time::Duration};

use nvml_wrapper::Nvml;
use opentelemetry::{KeyValue, global, trace::TracerProvider as _};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{
    ExporterBuildError, LogExporter, MetricExporter, SpanExporter, WithHttpConfig,
};
use opentelemetry_sdk::{
    Resource,
    error::OTelSdkError,
    logs::SdkLoggerProvider,
    metrics::{PeriodicReader, SdkMeterProvider},
    resource::ResourceDetector,
    trace::SdkTracerProvider,
};
use parking_lot::Mutex;
use sysinfo::System;
use tracing_subscriber::{
    EnvFilter, Registry, layer::SubscriberExt as _, util::SubscriberInitExt as _,
};

pub static HOSTNAME: LazyLock<String> = LazyLock::new(|| System::host_name().unwrap_or_default());
pub static NVML: LazyLock<Option<Nvml>> = LazyLock::new(|| Nvml::init().ok());
pub static SYS: LazyLock<Mutex<System>> = LazyLock::new(|| Mutex::new(System::new()));

pub struct Telemetry {
    tracer_provider: SdkTracerProvider,
    logger_provider: SdkLoggerProvider,
    meter_provider: SdkMeterProvider,
}

impl Telemetry {
    pub fn init(service_name: impl AsRef<str>) -> Result<Self, ExporterBuildError> {
        let resource = Resource::builder()
            .with_service_name(service_name.as_ref().to_owned())
            .with_attributes([KeyValue::new("hostname", HOSTNAME.as_str())])
            .with_detectors(&[Box::new(CpuDetector), Box::new(GpuDetector)])
            .build();

        let trace_exporter = SpanExporter::builder()
            .with_http()
            .with_headers(HashMap::from([(
                "x-greptime-pipeline-name".to_string(),
                "greptime_trace_v1".to_string(),
            )]))
            .build()?;
        let tracer_provider = SdkTracerProvider::builder()
            .with_batch_exporter(trace_exporter)
            .with_resource(resource.clone())
            .build();
        global::set_tracer_provider(tracer_provider.clone());

        let log_exporter = LogExporter::builder().with_http().build()?;
        let logger_provider = SdkLoggerProvider::builder()
            .with_batch_exporter(log_exporter)
            .with_resource(resource.clone())
            .build();

        let metric_exporter = MetricExporter::builder()
            .with_http()
            .with_headers(HashMap::from([(
                "x-greptime-otlp-metric-promote-resource-attrs".to_string(),
                "service.name;hostname;".to_string(),
            )]))
            .build()?;
        let metric_reader = PeriodicReader::builder(metric_exporter)
            .with_interval(Duration::from_secs(10))
            .build();
        let meter_provider = SdkMeterProvider::builder()
            .with_reader(metric_reader)
            .with_resource(resource)
            .build();
        global::set_meter_provider(meter_provider.clone());

        register_system_meters();

        let tracer = tracer_provider.tracer(service_name.as_ref().to_string());
        let trace_layer = tracing_opentelemetry::layer().with_tracer(tracer);
        let log_layer = OpenTelemetryTracingBridge::new(&logger_provider);

        Registry::default()
            .with(trace_layer)
            .with(log_layer)
            .with(tracing_subscriber::fmt::layer())
            .with(EnvFilter::from_default_env().add_directive("embed=info".parse().unwrap()))
            .init();

        Ok(Self {
            tracer_provider,
            logger_provider,
            meter_provider,
        })
    }

    pub fn shutdown(&self) -> Result<(), OTelSdkError> {
        self.tracer_provider.shutdown()?;
        self.logger_provider.shutdown()?;
        self.meter_provider.shutdown()?;
        Ok(())
    }
}

struct CpuDetector;

impl ResourceDetector for CpuDetector {
    fn detect(&self) -> Resource {
        let mut sys = (*SYS).lock();
        sys.refresh_memory();
        let total = sys.total_memory() as f32;
        let swap = sys.total_swap() as f32;
        Resource::builder()
            .with_attributes([
                KeyValue::new(
                    "cpu.memory.total",
                    format!("{:.2} GB", total / 1000f32.powi(3)),
                ),
                KeyValue::new(
                    "cpu.memory.swap",
                    format!("{:.2} GiB", swap / 1024f32.powi(3)),
                ),
            ])
            .build()
    }
}

struct GpuDetector;

impl ResourceDetector for GpuDetector {
    fn detect(&self) -> Resource {
        let mut builder = Resource::builder();

        let Some(nvml) = &*NVML else {
            return builder.build();
        };
        let Ok(count) = nvml.device_count() else {
            return builder.build();
        };

        for i in 0..count {
            let Ok(device) = nvml.device_by_index(i) else {
                continue;
            };
            let Ok(name) = device.name() else {
                continue;
            };
            let Ok(memory) = device.memory_info() else {
                continue;
            };
            builder = builder.with_attributes([
                KeyValue::new(format!("gpu.device-{i}.name"), name),
                KeyValue::new(
                    format!("gpu.device-{i}.memory.total"),
                    format!("{} GiB", memory.total as f32 / 1024f32.powi(3)),
                ),
            ]);
        }

        builder.build()
    }
}

pub fn register_system_meters() {
    let cpu = global::meter("cpu");
    cpu.f64_observable_gauge("cpu.usage")
        .with_description("global cpu usage")
        .with_unit("1")
        .with_callback(|i| {
            let mut sys = (*SYS).lock();
            sys.refresh_cpu_usage();
            let measurement = sys.global_cpu_usage() as f64;
            drop(sys);
            i.observe(measurement, &[]);
        })
        .build();
    let memory = global::meter("memory");
    memory
        .u64_observable_gauge("memory")
        .with_description("memory usage")
        .with_unit("B")
        .with_callback(|i| {
            let mut sys = (*SYS).lock();
            sys.refresh_memory();
            let measurement = sys.used_memory();
            drop(sys);
            i.observe(measurement, &[]);
        })
        .build();
    let gpu = global::meter("gpu");
    if let Some(nvml) = &*NVML
        && let Ok(count) = nvml.device_count()
    {
        for idx in 0..count {
            let Ok(device) = nvml.device_by_index(idx) else {
                continue;
            };
            gpu.u64_observable_gauge("gpu.memory")
                .with_unit("B")
                .with_callback(move |i| {
                    let Ok(mem_info) = device.memory_info() else {
                        return;
                    };
                    let measurement = mem_info.used;
                    i.observe(
                        measurement,
                        &[KeyValue::new("device_index", idx.to_string())],
                    );
                })
                .build();
            let Ok(device) = nvml.device_by_index(idx) else {
                continue;
            };
            gpu.u64_observable_gauge("gpu.memory.utilization")
                .with_unit("%")
                .with_callback(move |i| {
                    let Ok(utilization) = device.utilization_rates() else {
                        return;
                    };
                    let measurement = utilization.memory as u64;
                    i.observe(
                        measurement,
                        &[KeyValue::new("device_index", idx.to_string())],
                    );
                })
                .build();
            let Ok(device) = nvml.device_by_index(idx) else {
                continue;
            };
            gpu.u64_observable_gauge("gpu.utilization")
                .with_unit("%")
                .with_callback(move |i| {
                    let Ok(utilization) = device.utilization_rates() else {
                        return;
                    };
                    let measurement = utilization.gpu as u64;
                    i.observe(
                        measurement,
                        &[KeyValue::new("device_index", idx.to_string())],
                    );
                })
                .build();
        }
    }
}
