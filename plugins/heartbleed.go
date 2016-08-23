package plugins

import "crypto/tls"

// HeartBleedDetector Detect whether has heartblood vul
type HeartBleedDetector struct {
}

func NewHeartBleedDetector() *HeartBleedDetector {
	return &HeartBleedDetector{}
}

func (d HeartBleedDetector) Name() string {
	return "heartbleed"
}

func (d HeartBleedDetector) Detect(domain string, conn *tls.Conn) map[string]interface{} {
	return map[string]interface{}{}
}

var _ = PluginManager.Register(*NewHeartBleedDetector())
