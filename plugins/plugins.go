package plugins

import ct "github.com/google/certificate-transparency-go"

type Task struct {
	LogURI       string
	PrecertsOnly bool
	BatchSize    int64
	Concurrency  int
	StartIndex   int64
	EndIndex     int64
	Res          *Result
}

type Result struct {
	Success bool
	Err     error
}

type Starter interface {
	Start() (Scheduler, error)
}

type Scheduler interface {
	Next(task *Task) *Task
}

type Processor interface {
	ProcessPrecert(entry *ct.RawLogEntry)
	ProcessCert(entry *ct.RawLogEntry)
}

type Logger interface {
	Fatal(err error)
}

type Director interface {
	GetStarter() Starter
	GetProcessor() Processor
	GetLogger() Logger
}
