package main

import (
	"net"     // added for statsd communication
	"os"
	"regexp"
	"sort"    // added for statsd ordered tokens
	"strconv" // added for statsd event submission
	"strings" // added for statsd string formatting
	"syscall"
	"time"
)

const (
	EVENT_START = 1300 // Start of the audit type ids that we care about
	EVENT_END   = 1399 // End of the audit type ids that we care about
	EVENT_EOE   = 1320 // End of multi packet event
)

type AuditMarshaller struct {
	msgs          map[int]*AuditMessageGroup
	writer        *AuditWriter
	lastSeq       int
	missed        map[int]bool
	worstLag      int
	trackMessages bool
	logOutOfOrder bool
	maxOutOfOrder int
	attempts      int
	filters       map[string]map[uint16][]*regexp.Regexp // { syscall: { mtype: [regexp, ...] } }
	statsdConfigs StatsdConfig
}

type AuditFilter struct {
	messageType uint16
	regex       *regexp.Regexp
	syscall     string
}

type datagramFormatter struct {
	mtagbls		map[string]string
	tokens 		map[string]string
	content		string
	syscall		string
	comm		string
	event		bool
	arg_string	string
	tags		[]string
	etags		[]string
	uid_map		map[string]string
}

type statsdClient struct {
	conn net.Conn
}

type StatsdConfig struct {
	kind    string
	ip      string
	port    string
	tokens  map[uint16]map[string]string
}

func appendKeyTag(l []string, k1, k2, v string) ([]string) {
	if len(k1) > 0 {
		return append(l, k1 + v)
	}
	return append(l, k2 + v)
}

// get specific pieces of messages for metric name, tags
// TODO: This can probly be better done
func cutout(s1, s2 string) (string) {
	split_s1 := strings.Split(" " + s1, s2)
	if len(split_s1) < 2 {
		return "" 
	}
	sub_part := split_s1[1] + " "
	return sub_part[:strings.Index(sub_part, " ")]
}

// format the data for statsd or dogstatsd protocol
func formatDatagram(msg *AuditMessageGroup, confs *StatsdConfig) (string) {
	df := datagramFormatter {
		mtagbls: map[string]string{"comm": "", "success": "", "exit": "", "tty": "", "cwd": "",},
		tokens: map[string]string{},
		content: "",
		syscall: "",
		comm: "",
		event: false,
		arg_string: "",
		tags: []string{},
		etags: []string{},
		uid_map: msg.UidMap,
	}
	rtags := map[string]string{"auid": "", "uid": "", "name": "", "key": ""}
	var dat_gram string
	var arg_val string
	tag_delim := ":"
	if confs.kind == "statsd" {
		tag_delim = "_"
	}
	
	for _, mes := range msg.Msgs {
		cont := string(" " + strings.Replace(mes.Data, "\"", "", -1) + " ")
		df.content += cont
		// el.Println("found mes.Type: ", mes.Type)
		if _, it := confs.tokens[mes.Type]; it {
			// el.Println("config token matched on item type: ", mes.Type)
			for k, v := range confs.tokens[mes.Type] {
				// el.Println("attempting cutout of token: ", k, v, ":", cutout(cont, " " + k + "="))
				if val := cutout(cont, " " + k + "="); val != "" {
					df.tokens[k] = val
					if _, ok := df.mtagbls[k]; ok {
						df.tags = appendKeyTag(df.tags, v, k, tag_delim + val)
					} else if _, ok := rtags[k]; !ok {
						df.etags = appendKeyTag(df.etags, v, k, tag_delim + val)
					}
				}
			}
		}
		// add special stuff
		switch mes.Type{
		case 1300:
			if sys := cutout(cont, " syscall="); sys == "" {
				return ""
			} else {
				df.syscall = sys
			}
			if com := cutout(cont, " comm="); com != "" {
				df.comm = com
			}
			if key := cutout(cont, " key="); key != "" {
				for _, i := range strings.Split(key, ",") {
					if i == "event" {
						df.event = true
					} else if v, ok := confs.tokens[mes.Type]["key"]; ok {
						df.tags = appendKeyTag(df.tags, v, "key", tag_delim + i)
						if len(strings.Split(i, ":")) > 1 {
							df.tags = append(df.tags, strings.Replace(i, ":", tag_delim, -1))
						}
					}
				}
			}
		case 1302:
			if n, ok := df.tokens["name"]; ok {
				if nt := cutout(cont, " nametype="); nt == "NORMAL" {
					df.etags = appendKeyTag(df.etags, confs.tokens[mes.Type]["name"], "name", tag_delim + n)
				}
			}
		case 1309:
			if _, i := confs.tokens[mes.Type]; i {
				if _, a := confs.tokens[mes.Type]["args"]; a {
					df.arg_string = cont
				}
			}
		}
	}

	// arg stuff
	if df.arg_string != "" && df.comm != "" {
		arg_val = cutout(df.arg_string, df.comm + " ")
        arg_val = strings.TrimSpace(arg_val[strings.Index(arg_val, "=")+1:])
        if arg_val != "" {
        	df.tags = appendKeyTag(df.tags, confs.tokens[uint16(1309)]["args"], "arg", tag_delim + arg_val)
        }
	}
	
	// users
	for _, ut := range []string{"uid", "auid"} {
		if u, ok := confs.tokens[uint16(1300)][ut]; ok {
			df.tags = appendKeyTag(df.tags, u, ut, tag_delim + df.uid_map[df.tokens[ut]])
		}
	}

	// format dat_gram
	// if dogstatsd, and if not event, tag only with tagables
	if len(df.syscall) > 0 {
		if confs.kind == "dogstatsd" {
			if df.event == false {
				dat_gram = "goaudit.syscall." + df.syscall + ".count:1|c"
				if len(df.tags) > 0 {
					sort.Strings(df.tags)
					dat_gram += string("|#" + strings.Join(df.tags, ","))
				}
			} else {
				evnt_t := "Go-Audit Syscall " + df.syscall + " ocurred"
				if _, ok := df.tokens["key"]; ok {
					evnt_t += " and matched on Key Group " + strings.Replace(strings.Replace(df.tokens["key"], ",event", "", -1), "event,", "", -1)
				}
				dat_gram = "_e{" + strconv.Itoa(len(evnt_t)) + "," + strconv.Itoa(len(df.content)) + "}:" + evnt_t + "|" + df.content + "|s:goaudit"
				df.tags = append(df.tags, df.etags...)  
				if len(df.tags) > 0 {
					sort.Strings(df.tags)
					dat_gram += string("|#" + strings.Join(df.tags, ","))
				}
			}
		} else if confs.kind == "statsd" {
			dat_gram = "goaudit.syscall." + df.syscall + ".count"
			df.tags = append(df.tags, df.etags...) 
        	        if len(df.tags) > 0 {
        	        	sort.Strings(df.tags)
        	        	dat_gram += string("." + strings.Join(df.tags, "."))
        	        }       
        	        dat_gram += ":1|c"
		}
	}
	// el.Println("event cont:", df.content)
	return dat_gram
}

// create statsd connection
func newStatsdClient(addr string) (*statsdClient, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, err
	}
	client := &statsdClient{conn: conn}
	return client, nil
}

// marshaller method for sending data over statsd or dogstatsd
func (a *AuditMarshaller) sendDatagram(msg *AuditMessageGroup) (error) {
	// This will format the messages into a datagram for either statsd or dogstatsd depending on configuration
	data_gram := formatDatagram(msg, &a.statsdConfigs)
	if data_gram == "" {
		return nil
	}
	udp_cl, err := newStatsdClient(a.statsdConfigs.ip + ":" + a.statsdConfigs.port)
	el.Println("sending datagram to address " + a.statsdConfigs.ip + ":" + a.statsdConfigs.port + " with content:", data_gram)
	if err != nil {
		return err
	}
	defer udp_cl.conn.Close()
	udp_cl.conn.Write([]byte(data_gram))
	return nil
}

// Create a new marshaller
func NewAuditMarshaller(w *AuditWriter, trackMessages, logOOO bool, maxOOO int, filters []AuditFilter, statsdConfigs StatsdConfig) *AuditMarshaller {
	am := AuditMarshaller{
		writer:        w,
		msgs:          make(map[int]*AuditMessageGroup, 5), // It is not typical to have more than 2 message groups at any given time
		missed:        make(map[int]bool, 10),
		trackMessages: trackMessages,
		logOutOfOrder: logOOO,
		maxOutOfOrder: maxOOO,
		filters:       make(map[string]map[uint16][]*regexp.Regexp),
		statsdConfigs: statsdConfigs,
	}

	for _, filter := range filters {
		if _, ok := am.filters[filter.syscall]; !ok {
			am.filters[filter.syscall] = make(map[uint16][]*regexp.Regexp)
		}

		if _, ok := am.filters[filter.syscall][filter.messageType]; !ok {
			am.filters[filter.syscall][filter.messageType] = []*regexp.Regexp{}
		}

		am.filters[filter.syscall][filter.messageType] = append(am.filters[filter.syscall][filter.messageType], filter.regex)
	}

	return &am
}

// Ingests a netlink message and likely prepares it to be logged
func (a *AuditMarshaller) Consume(nlMsg *syscall.NetlinkMessage) {
	aMsg := NewAuditMessage(nlMsg)

	if aMsg.Seq == 0 {
		// We got an invalid audit message, return the current message and reset
		a.flushOld()
		return
	}

	if a.trackMessages {
		a.detectMissing(aMsg.Seq)
	}

	if nlMsg.Header.Type < EVENT_START || nlMsg.Header.Type > EVENT_END {
		// Drop all audit messages that aren't things we care about or end a multi packet event
		a.flushOld()
		return
	} else if nlMsg.Header.Type == EVENT_EOE {
		// This is end of event msg, flush the msg with that sequence and discard this one
		a.completeMessage(aMsg.Seq)
		return
	}

	if val, ok := a.msgs[aMsg.Seq]; ok {
		// Use the original AuditMessageGroup if we have one
		val.AddMessage(aMsg)
	} else {
		// Create a new AuditMessageGroup
		a.msgs[aMsg.Seq] = NewAuditMessageGroup(aMsg)
	}

	a.flushOld()
}

// Outputs any messages that are old enough
// This is because there is no indication of multi message events coming from kaudit
func (a *AuditMarshaller) flushOld() {
	now := time.Now()
	for seq, msg := range a.msgs {
		if msg.CompleteAfter.Before(now) || now.Equal(msg.CompleteAfter) {
			a.completeMessage(seq)
		}
	}
}

// Write a complete message group to the configured output in json format
func (a *AuditMarshaller) completeMessage(seq int) {
	var msg *AuditMessageGroup
	var ok bool

	if msg, ok = a.msgs[seq]; !ok {
		//TODO: attempted to complete a missing message, log?
		return
	}

	if a.dropMessage(msg) {
		delete(a.msgs, seq)
		return
	}
	
	if a.statsdConfigs.kind == "statsd" || a.statsdConfigs.kind == "dogstatsd" {
		if err := a.sendDatagram(msg); err != nil {
			el.Println("Failed to send statsd datagram. Error:", err)
		}
	}

	if err := a.writer.Write(msg); err != nil {
		el.Println("Failed to write message. Error:", err)
		os.Exit(1)
	}

	delete(a.msgs, seq)
}

func (a *AuditMarshaller) dropMessage(msg *AuditMessageGroup) bool {
	filters, ok := a.filters[msg.Syscall]
	if !ok {
		return false
	}

	for _, msg := range msg.Msgs {
		if fg, ok := filters[msg.Type]; ok {
			for _, filter := range fg {
				if filter.MatchString(msg.Data) {
					return true
				}
			}
		}
	}

	return false
}

// Track sequence numbers and log if we suspect we missed a message
func (a *AuditMarshaller) detectMissing(seq int) {
	if seq > a.lastSeq+1 && a.lastSeq != 0 {
		// We likely leap frogged over a msg, wait until the next sequence to make sure
		for i := a.lastSeq + 1; i < seq; i++ {
			a.missed[i] = true
		}
	}

	for missedSeq, _ := range a.missed {
		if missedSeq == seq {
			lag := a.lastSeq - missedSeq
			if lag > a.worstLag {
				a.worstLag = lag
			}

			if a.logOutOfOrder {
				el.Println("Got sequence", missedSeq, "after", lag, "messages. Worst lag so far", a.worstLag, "messages")
			}
			delete(a.missed, missedSeq)
		} else if seq-missedSeq > a.maxOutOfOrder {
			el.Printf("Likely missed sequence %d, current %d, worst message delay %d\n", missedSeq, seq, a.worstLag)
			delete(a.missed, missedSeq)
		}
	}

	if seq > a.lastSeq {
		// Keep track of the largest sequence
		a.lastSeq = seq
	}
}
