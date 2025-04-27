package middleware

import (
	"context"
	"time"

	"user_project/pkg/logger"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelCodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func InitTracer() (*sdktrace.TracerProvider, error) {
	exporter, err := otlptracegrpc.New(context.Background(),
		otlptracegrpc.WithEndpoint("host.docker.internal:4317"),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter,
			sdktrace.WithBatchTimeout(5*time.Second),
			sdktrace.WithMaxExportBatchSize(10),
		),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("credit-origination-service"),
			attribute.String("environment", "development"),
		)),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	logger.Logger.Info("Tracer provider initialized")
	return tp, nil
}

func TracingInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	ctx = extractTraceContext(ctx)

	ctx, span := otel.Tracer("grpc").Start(ctx, info.FullMethod,
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			semconv.RPCSystemGRPC,
			semconv.RPCServiceKey.String("credit.origination.v1"),
			semconv.RPCMethodKey.String(info.FullMethod),
		))
	defer span.End()

	startTime := time.Now()
	logger.Logger.Debug("Starting request",
		zap.String("method", info.FullMethod),
		zap.String("trace_id", span.SpanContext().TraceID().String()),
		zap.String("span_id", span.SpanContext().SpanID().String()),
	)

	res, err := handler(ctx, req)
	duration := time.Since(startTime)

	statusCode := codes.OK
	otelStatus := otelCodes.Ok
	var statusMessage string

	if err != nil {
		if s, ok := status.FromError(err); ok {
			statusCode = s.Code()
			otelStatus = otelCodes.Error
			statusMessage = s.Message()
		} else {
			otelStatus = otelCodes.Error
			statusMessage = err.Error()
		}
		span.SetStatus(otelStatus, statusMessage)
		span.RecordError(err)
	} else {
		statusMessage = "OK"
		span.SetStatus(otelStatus, statusMessage)
	}

	span.SetAttributes(
		semconv.RPCGRPCStatusCodeKey.Int64(int64(statusCode)),
	)

	logger.Logger.Info("Request completed",
		zap.String("method", info.FullMethod),
		zap.Duration("duration", duration),
		zap.String("trace_id", span.SpanContext().TraceID().String()),
		zap.String("span_id", span.SpanContext().SpanID().String()),
		zap.String("status", statusCode.String()),
		zap.Error(err),
	)

	return res, err
}

func extractTraceContext(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}

	ctx = otel.GetTextMapPropagator().Extract(ctx, propagation.HeaderCarrier(md))

	if traceParent := md.Get("traceparent"); len(traceParent) > 0 {
		ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("traceparent", traceParent[0]))
	}

	return ctx
}
