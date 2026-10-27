"""Optional OpenTelemetry tracing. A no-op unless `opentelemetry-api` is installed.

Spans carry only content-free attributes (tenant, purpose, counts, statuses, reason
codes) - never item IDs, prompts or request payloads.
"""
from __future__ import annotations
import os
from contextlib import contextmanager

try:
    from opentelemetry import trace as _trace
except ImportError:  # tracing is optional
    _trace = None


@contextmanager
def span(name: str, **attributes):
    if _trace is None:
        yield None
        return
    with _trace.get_tracer("recguard").start_as_current_span(name) as current:
        set_attributes(current, **attributes)
        yield current


def set_attributes(current, **attributes):
    if current is None:
        return
    for key, value in attributes.items():
        if value is not None:
            current.set_attribute(f"recguard.{key}", value)


def configure_from_environment(app=None) -> bool:
    """Export spans over OTLP/HTTP when RECGUARD_OTEL=1 or OTEL_EXPORTER_OTLP_ENDPOINT is set.

    Uses the standard OTEL_* variables (endpoint, headers, service name). Instruments the
    FastAPI app too when opentelemetry-instrumentation-fastapi is installed.
    """
    if not (os.getenv("RECGUARD_OTEL") == "1" or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")):
        return False
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        raise RuntimeError("Tracing needs: pip install 'recguard-kernel[otel]'") from None
    provider = TracerProvider(resource=Resource.create({"service.name": os.getenv("OTEL_SERVICE_NAME", "recguard")}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    _trace.set_tracer_provider(provider)
    if app is not None:
        try:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
            FastAPIInstrumentor.instrument_app(app)
        except ImportError:
            pass
    return True
