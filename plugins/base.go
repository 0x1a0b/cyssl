package plugins

import "crypto/tls"

// BaseDetector interface for all plugin detector, detector that implements
// `Name` and `Detect` method is a BaseDetector
type BaseDetector interface {
	Name() string
	Detect(domain string, conn *tls.Conn) map[string]interface{}
}

type pluginManager struct {
	Detectors []BaseDetector
}

func (p *pluginManager) Register(detector BaseDetector) int {
	p.Detectors = append(p.Detectors, detector)
	return len(p.Detectors)
}

// PluginManager global var to store all detector plugins
var PluginManager = &pluginManager{}
