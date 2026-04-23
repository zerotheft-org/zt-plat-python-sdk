import logging
import os
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry._logs import set_logger_provider
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter
from opentelemetry.sdk._logs import LoggingHandler
from opentelemetry.sdk.resources import OTELResourceDetector

logger = logging.getLogger(__name__)

def configure_telemetry() -> None:
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        logger.warning("OTEL_EXPORTER_OTLP_ENDPOINT not set — telemetry disabled")
        return

    try:
        _setup_traces()
        _setup_metrics()
        _setup_logs()
        logger.info(
            "OpenTelemetry configured → %s  service=%s",
            endpoint,
            os.getenv("OTEL_SERVICE_NAME", "unknown"),
        )
    except Exception:
        logger.exception("Failed to configure OpenTelemetry — continuing without it")


def instrument_app(app) -> None:
    """
    Call this AFTER create_application() returns, passing the FastAPI app.
    Required because FastAPIInstrumentor must hook into an existing app instance.
    """
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        FastAPIInstrumentor.instrument_app(app)
        logger.info("FastAPI instrumented")
    except Exception as exc:
        logger.warning("Could not instrument FastAPI: %s", exc)

#  Traces

def _setup_traces() -> None:
    resource = _build_resource()
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)

    # Instrument everything except FastAPI (handled separately in instrument_app)
    _instrument_libraries()

def _instrument_libraries() -> None:
    instrumentors = [
        ("opentelemetry.instrumentation.sqlalchemy", "SQLAlchemyInstrumentor", {}),
        ("opentelemetry.instrumentation.redis",      "RedisInstrumentor",      {}),
        ("opentelemetry.instrumentation.httpx",      "HTTPXClientInstrumentor",{}),
        ("opentelemetry.instrumentation.celery",     "CeleryInstrumentor",     {}),
        ("opentelemetry.instrumentation.requests",   "RequestsInstrumentor",   {}),
        ("opentelemetry.instrumentation.logging",    "LoggingInstrumentor",
            {"set_logging_format": True}),
    ]
    for module_path, class_name, kwargs in instrumentors:
        try:
            mod = __import__(module_path, fromlist=[class_name])
            cls = getattr(mod, class_name)
            cls().instrument(**kwargs)
        except ImportError:
            pass
        except Exception as exc:
            logger.warning("Could not instrument %s: %s", class_name, exc)

# Metrics

def _setup_metrics() -> None:
    resource = _build_resource()
    reader = PeriodicExportingMetricReader(OTLPMetricExporter(), export_interval_millis=30_000)
    provider = MeterProvider(resource=resource, metric_readers=[reader])
    metrics.set_meter_provider(provider)

# Logs

def _setup_logs() -> None:
    resource = _build_resource()
    provider = LoggerProvider(resource=resource)
    provider.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter()))
    set_logger_provider(provider)

    handler = LoggingHandler(level=logging.NOTSET, logger_provider=provider)
    logging.getLogger().addHandler(handler)

# Shared resource

def _build_resource():
    detected = OTELResourceDetector().detect()
    base = Resource.create({"service.name": os.getenv("OTEL_SERVICE_NAME", "unknown-service")})
    return base.merge(detected)