package backend

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

const (
	DEFAULT_ENDPOINT = "lain"
)

type openFalconMsg struct {
	Metric      string  `json:"metric"`
	Endpoint    string  `json:"endpoint"`
	Tags        string  `json:"tags"`
	Value       float64 `json:"value"`
	Timestamp   int64   `json:"timestamp"`
	CounterType string  `json:"counterType"`
	Step        int64   `json:"step"`
}

type OpenFalconBackend struct {
	addr    string
	postUrl string
	packets []*openFalconMsg
}

func NewOpenFalconBackend(addr string) (Backend, error) {
	bd := &OpenFalconBackend{
		addr:    addr,
		postUrl: fmt.Sprintf("http://%s/v1/push", addr),
	}
	return bd, nil
}

// Send sends metric value to hostname
func (g *OpenFalconBackend) Send(metrics []*Metric, logger *zap.Logger) {
	var packets []*openFalconMsg
	for _, m := range metrics {
		var tagSlice []string
		for k, v := range m.Tags {
			tagSlice = append(tagSlice, fmt.Sprintf("%s=%s", k, v))
		}

		pkt := &openFalconMsg{
			Metric:      m.Path,
			Endpoint:    DEFAULT_ENDPOINT,
			Tags:        strings.Join(tagSlice, ","),
			Value:       m.Value,
			Timestamp:   m.Timestamp.Unix(),
			CounterType: "GAUGE",
			Step:        m.Step,
		}
		packets = append(packets, pkt)
	}
	if len(packets) == 0 {
		return
	}
	buffer, err := json.Marshal(packets)
	if err != nil {
		logger.Error("Marhal Failed: ", zap.Any("packets", packets), zap.Error(err))
		return
	}
	req, err := http.NewRequest("POST", g.postUrl, bytes.NewBuffer(buffer))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Client.Do() Failed: ", zap.Error(err))
		return
	}
	defer resp.Body.Close()
	logger.Info("OpenFalconBackend.Send() succeed.", zap.Any("nb_metrics", len(metrics)))
}

// Close close the underlying connection
func (g *OpenFalconBackend) Close() error {
	return nil
}
