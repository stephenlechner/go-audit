package main

import (
	"net"
	"sort"
	"strconv"
	"strings"
)

type datagramFormatter struct {
	mtagbls    map[string]string
	tokens     map[string]string
	content    string
	syscall    string
	comm       string
	event      bool
	arg_string string
	tags       []string
	etags      []string
	uid_map    map[string]string
}

type statsdClient struct {
	conn net.Conn
}

type StatsdConfig struct {
	kind   string
	ip     string
	port   string
	tokens map[uint16]map[string]string
}

func appendKeyTag(l []string, k1, k2, v string) []string {
	if len(k1) > 0 {
		return append(l, k1+v)
	}
	return append(l, k2+v)
}

// get specific pieces of messages for metric name, tags
// TODO: This can probly be better done
func cutout(s1, s2 string) string {
	split_s1 := strings.Split(" "+s1, s2)
	if len(split_s1) < 2 {
		return ""
	}
	sub_part := split_s1[1] + " "
	return sub_part[:strings.Index(sub_part, " ")]
}

// format the data for statsd or dogstatsd protocol
func formatDatagram(msg *AuditMessageGroup, confs *StatsdConfig) string {
	df := datagramFormatter{
		mtagbls:    map[string]string{"comm": "", "success": "", "exit": "", "tty": "", "cwd": ""},
		tokens:     map[string]string{},
		content:    "",
		syscall:    "",
		comm:       "",
		event:      false,
		arg_string: "",
		tags:       []string{},
		etags:      []string{},
		uid_map:    msg.UidMap,
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
				if val := cutout(cont, " "+k+"="); val != "" {
					df.tokens[k] = val
					if _, ok := df.mtagbls[k]; ok {
						df.tags = appendKeyTag(df.tags, v, k, tag_delim+val)
					} else if _, ok := rtags[k]; !ok {
						df.etags = appendKeyTag(df.etags, v, k, tag_delim+val)
					}
				}
			}
		}
		// add special stuff
		switch mes.Type {
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
						df.tags = appendKeyTag(df.tags, v, "key", tag_delim+i)
						if len(strings.Split(i, ":")) > 1 {
							df.tags = append(df.tags, strings.Replace(i, ":", tag_delim, -1))
						}
					}
				}
			}
		case 1302:
			if n, ok := df.tokens["name"]; ok {
				if nt := cutout(cont, " nametype="); nt == "NORMAL" {
					df.etags = appendKeyTag(df.etags, confs.tokens[mes.Type]["name"], "name", tag_delim+n)
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
		arg_val = cutout(df.arg_string, df.comm+" ")
		arg_val = strings.TrimSpace(arg_val[strings.Index(arg_val, "=")+1:])
		if arg_val != "" {
			df.tags = appendKeyTag(df.tags, confs.tokens[uint16(1309)]["args"], "arg", tag_delim+arg_val)
		}
	}

	// users
	for _, ut := range []string{"uid", "auid"} {
		if u, ok := confs.tokens[uint16(1300)][ut]; ok {
			df.tags = appendKeyTag(df.tags, u, ut, tag_delim+df.uid_map[df.tokens[ut]])
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
