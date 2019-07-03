package slack

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"text/template"
	"time"
)

type Notifier struct {
	URL          string
	Channel      string
	Username     string
	IconEmoji    string
	TextTemplate *template.Template
	Debounce     time.Duration

	mu               sync.Mutex
	nextEvents       []eventData
	nextNotification *time.Timer
}

var defaultTemplate = template.Must(template.New("default").Parse("{{ range .Events }}`{{ .User }}` connected to `{{ .Upstream }}` from `{{ .RemoteIP }}`{{ with .RemoteIPDesc }} ({{ . }}){{ end }}\n{{ end }}"))

func (n *Notifier) buildMessage(data messageData) (*message, error) {
	msg := message{
		Channel:   n.Channel,
		Username:  n.Username,
		IconEmoji: n.IconEmoji,
	}
	template := n.TextTemplate
	if template == nil {
		template = defaultTemplate
	}
	var buf bytes.Buffer
	if err := template.Execute(&buf, data); err != nil {
		return nil, err
	}
	msg.Text = buf.String()
	return &msg, nil
}

type eventData struct {
	User         string
	RemoteIP     string
	RemoteIPDesc string
	Upstream     string
}

type messageData struct {
	Events []eventData
}

type message struct {
	Channel   string `json:"channel,omitempty"`
	Username  string `json:"username,omitempty"`
	Text      string `json:"text,omitempty"`
	IconEmoji string `json:"icon_emoji,omitempty"`
}

func (n *Notifier) flush(events []eventData) error {
	if len(events) == 0 {
		return nil
	}
	var uniqueEvents []eventData
	seenEvents := make(map[eventData]struct{})
	for _, event := range events {
		if _, seen := seenEvents[event]; seen {
			continue
		}
		uniqueEvents = append(uniqueEvents, event)
		seenEvents[event] = struct{}{}
	}
	msg, err := n.buildMessage(messageData{
		Events: uniqueEvents,
	})
	if err != nil {
		return err
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	values := make(url.Values)
	values.Set("payload", string(payload))
	res, err := http.PostForm(n.URL, values)
	if err != nil {
		return err
	}
	io.Copy(ioutil.Discard, res.Body)
	res.Body.Close()
	return nil
}

func (n *Notifier) NotifyConnect(user, remoteIP, remoteIPDesc, upstream string) error {
	if n == nil || n.URL == "" {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.nextEvents = append(n.nextEvents, eventData{
		User:         user,
		RemoteIP:     remoteIP,
		RemoteIPDesc: remoteIPDesc,
		Upstream:     upstream,
	})
	debounce := n.Debounce
	if debounce == 0 {
		debounce = time.Minute
	}
	if n.nextNotification == nil {
		n.nextNotification = time.AfterFunc(debounce, func() {
			n.mu.Lock()
			events := n.nextEvents
			n.nextEvents = nil
			n.nextNotification = nil
			n.mu.Unlock()
			n.flush(events)
		})
	}
	return nil
}
