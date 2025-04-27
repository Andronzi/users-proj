package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var Logger *zap.Logger

func InitLogger() {
	logWriter := &lumberjack.Logger{
		Filename:   "/var/log/myapp.log",
		MaxSize:    10,
		MaxBackups: 5,
		MaxAge:     30,
		Compress:   true,
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoder := zapcore.NewJSONEncoder(encoderConfig)
	writeSyncer := zapcore.AddSync(logWriter)

	// TODO: DebugLevel применим только в dev режиме. Подумать над разграничением prod, dev
	core := zapcore.NewCore(encoder, writeSyncer, zap.DebugLevel)

	Logger = zap.New(core, zap.AddCaller())
}
