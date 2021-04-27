package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/certificate-transparency-go/x509"
	"gopkg.in/yaml.v2"
)

func Gao(task *Task, director Director) *Result {
	res := &Result{
		Success: true,
		Err:     nil,
	}
	logClient, err := client.New(task.LogURI, &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, jsonclient.Options{UserAgent: "ct-amigo-scanlog/1.0"})
	if err != nil {
		director.GetLogger().Fatal(err)
	}
	opts := scanner.ScannerOptions{
		FetcherOptions: scanner.FetcherOptions{
			BatchSize:     int(task.BatchSize),
			ParallelFetch: task.Concurrency,
			StartIndex:    task.StartIndex,
			EndIndex:      task.EndIndex,
		},
	}
	s := scanner.NewScanner(logClient, opts)

	ctx := context.Background()
	err = s.Scan(ctx, director.GetProcessor().ProcessCert, director.GetProcessor().ProcessPrecert)
	if err != nil {
		director.GetLogger().Fatal(err)
		res.Success = false
		res.Err = err
	}
	return res
}

type MillionSalaryDirector struct {
	starter   *SimpleStarter
	processor *SimpleProcessor
	logger    *SimpleLogger
}

func HireMillionSalaryDirector() Director {
	return &MillionSalaryDirector{
		starter:   &SimpleStarter{},
		processor: &SimpleProcessor{dumpDir: "./"},
		logger:    &SimpleLogger{},
	}
}

func (msd *MillionSalaryDirector) GetStarter() Starter {
	return msd.starter
}

func (msd *MillionSalaryDirector) GetProcessor() Processor {
	return msd.processor
}

func (msd *MillionSalaryDirector) GetLogger() Logger {
	return msd.logger
}

type SimpleScheduler struct {
	LogURI       string `json:"uri"`
	CurrentBatch uint   `json:"current"`
	BatchSize    uint   `json:"batchSize"`
	SaveData     string `json:"saveData"`
	Start        uint   `json:"start"`
	End          uint   `json:"end"`
}

func (s *SimpleScheduler) Next(task *Task) *Task {
	// todo: make check point

	return &Task{
		LogURI:       task.LogURI,
		PrecertsOnly: task.PrecertsOnly,
		BatchSize:    task.BatchSize,
		Concurrency:  task.Concurrency,
		StartIndex:   task.StartIndex + task.BatchSize,
		EndIndex:     task.EndIndex,
		Res:          nil,
	}
}

type SimpleProcessor struct {
	dumpDir string
}

func dumpData(entry *ct.RawLogEntry, dumpDir string) {
	prefix := "unknown"
	suffix := "unknown"
	switch eType := entry.Leaf.TimestampedEntry.EntryType; eType {
	case ct.X509LogEntryType:
		prefix = "cert"
		suffix = "leaf"
	case ct.PrecertLogEntryType:
		prefix = "precert"
		suffix = "precert"
	default:
		log.Printf("Unknown log entry type %d", eType)
	}

	if len(entry.Cert.Data) > 0 {
		name := fmt.Sprintf("%s-%014d-%s.der", prefix, entry.Index, suffix)
		filename := path.Join(dumpDir, name)
		if err := ioutil.WriteFile(filename, entry.Cert.Data, 0644); err != nil {
			log.Printf("Failed to dump data for %s at index %d: %v", prefix, entry.Index, err)
		}
	}

	for ii := 0; ii < len(entry.Chain); ii++ {
		name := fmt.Sprintf("%s-%014d-%02d.der", prefix, entry.Index, ii)
		filename := path.Join(dumpDir, name)
		if err := ioutil.WriteFile(filename, entry.Chain[ii].Data, 0644); err != nil {
			log.Printf("Failed to dump data for CA at index %d: %v", entry.Index, err)
		}
	}
}

func (sp *SimpleProcessor) ProcessPrecert(entry *ct.RawLogEntry) {
	parsedEntry, err := entry.ToLogEntry()
	if x509.IsFatal(err) || parsedEntry.Precert == nil {
		log.Printf("Process precert at index %d: <unparsed: %v>", entry.Index, err)
	} else {
		log.Printf("Process precert at index %d: CN: '%s' Issuer: %s", entry.Index, parsedEntry.Precert.TBSCertificate.Subject.CommonName, parsedEntry.Precert.TBSCertificate.Issuer.CommonName)
	}
	dumpData(entry, sp.dumpDir)
}

func (sp *SimpleProcessor) ProcessCert(entry *ct.RawLogEntry) {
	parsedEntry, err := entry.ToLogEntry()
	if x509.IsFatal(err) || parsedEntry.X509Cert == nil {
		log.Printf("Process cert at index %d: <unparsed: %v>", entry.Index, err)
	} else {
		log.Printf("Process cert at index %d: CN: '%s'", entry.Index, parsedEntry.X509Cert.Subject.CommonName)
	}
	dumpData(entry, sp.dumpDir)
}

type SimpleLogger struct {
}

func (sl *SimpleLogger) Fatal(err error) {
	fmt.Println(err)
}

type SimpleConfig struct {
	LogURI      string `yaml:"uri"`
	SaveData    string `yaml:"save_data"`
	BatchSize   uint   `yaml:"batch_size"`
	Concurrency string `yaml:"concurrency"`
	Start       uint   `yaml:"start"`
	End         uint   `yaml:"end"`
}

type SimpleStarter struct {
}

func (ss *SimpleStarter) Start() (Scheduler, error) {
	content, err := ioutil.ReadFile("simple.yaml")
	if err != nil {
		return nil, err
	}

	var conf SimpleConfig
	err = yaml.Unmarshal(content, &conf)
	if err != nil {
		return nil, err
	}

	saved, err := ioutil.ReadFile(conf.SaveData)
	if err == nil {
		var data SimpleScheduler
		err = json.Unmarshal(saved, &data)
		if err != nil {
			return nil, err
		}
		return &data, nil
	} else {
		return &SimpleScheduler{
			LogURI:       conf.LogURI,
			CurrentBatch: 0,
			SaveData:     conf.SaveData,
			BatchSize:    conf.BatchSize,
			Start:        conf.Start,
			End:          conf.End,
		}, nil
	}
}
