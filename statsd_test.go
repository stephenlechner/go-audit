package main

import (
	"testing"
)

type cutout_test struct {
	s1     string
	s2     string
	result string
}

func Test_cutout(t *testing.T) {
	var ts = []cutout_test{
		{"hi there. findwaldo in this", "find", "waldo"},
		{"hi there. find empty string in this", "find", ""},
		{"findwaldo in this", "find", "waldo"},
		{"hi there. findwaldo", "find", "waldo"},
		{"findwaldo", "find", "waldo"},
		{"hi there. do not find waldo in this", "findnothing", ""},
		{"hi there. this should give an empty string. find", "find", ""},
		{"hi there. findgeorge and not findwaldo here", "find", "george"},
	}
	for _, ta := range ts {
		if r := cutout(ta.s1, ta.s2); r != ta.result {
			t.Error(
				"For", ta.s2, "in", ta.s1,
				"expected", ta.result,
				"got", r,
			)
		}
	}
}

type datagram_test struct {
	msg    *AuditMessageGroup
	sc     *StatsdConfig
	result string
}

func Test_formatDatagram(t *testing.T) {

	// test statsd
	// test dogstatsd metrics
	// test dogstatsd events

	var ts = []datagram_test{
		// blank result
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: "hi there tag=waldo this results in blank"}}}, &StatsdConfig{kind: "statsd"}, ""},
		// test basic statsd
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo syscall=test hi"}}}, &StatsdConfig{kind: "statsd"}, "goaudit.syscall.test.count:1|c"},
		// test statsd with unaliased token
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo syscall=test hi"}}}, &StatsdConfig{kind: "statsd", tokens: map[uint16]map[string]string{uint16(1300): {"tag": ""}}}, "goaudit.syscall.test.count.tag_waldo:1|c"},
		// test statsd with aliased token
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo syscall=test hi"}}}, &StatsdConfig{kind: "statsd", tokens: map[uint16]map[string]string{uint16(1300): {"tag": "name"}}}, "goaudit.syscall.test.count.name_waldo:1|c"},
		// test basic dogstatsd
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo syscall=test hi"}}}, &StatsdConfig{kind: "dogstatsd"}, "goaudit.syscall.test.count:1|c"},
		// test dogstatsd with untaggable token
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo syscall=test hi"}}}, &StatsdConfig{kind: "dogstatsd", tokens: map[uint16]map[string]string{uint16(1300): {"tag": "name"}}}, "goaudit.syscall.test.count:1|c"},
		// test dogststasd with tagable unaliased token
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo syscall=test success=yes exit=0 hi"}}}, &StatsdConfig{kind: "dogstatsd", tokens: map[uint16]map[string]string{uint16(1300): {"success": ""}}}, "goaudit.syscall.test.count:1|c|#success:yes"},
		// test dogstatsd with taggable aliased token
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo syscall=test success=yes exit=0 hi"}}}, &StatsdConfig{kind: "dogstatsd", tokens: map[uint16]map[string]string{uint16(1300): {"success": "worked"}}}, "goaudit.syscall.test.count:1|c|#worked:yes"},
		// test basic dogstatsd events
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo syscall=test key=event hi"}}}, &StatsdConfig{kind: "dogstatsd"}, "_e{29,47}:Go-Audit Syscall test ocurred|  hi there tag=waldo syscall=test key=event hi |s:goaudit"},
		// test dogstastd events with unaliased tokens
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo syscall=test key=event,foo hi"}}}, &StatsdConfig{kind: "dogstatsd", tokens: map[uint16]map[string]string{uint16(1300): {"key": ""}}}, "_e{58,51}:Go-Audit Syscall test ocurred and matched on Key Group foo|  hi there tag=waldo syscall=test key=event,foo hi |s:goaudit|#key:foo"},
		// test dogstatsd events with aliased tokens
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo syscall=test key=event,foo hi"}}}, &StatsdConfig{kind: "dogstatsd", tokens: map[uint16]map[string]string{uint16(1300): {"key": "rule_group"}}}, "_e{58,51}:Go-Audit Syscall test ocurred and matched on Key Group foo|  hi there tag=waldo syscall=test key=event,foo hi |s:goaudit|#rule_group:foo"},
		// test args token in statsd, unaliased
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo syscall=test comm=hello hi"}, &AuditMessage{Type: uint16(1309), Data: "argc=3 a0=\"hello\" a1=\"foo\" a2=\""}}}, &StatsdConfig{kind: "statsd", tokens: map[uint16]map[string]string{uint16(1309): {"args": ""}}}, "goaudit.syscall.test.count.arg_foo:1|c"},
		// test args token in statsd, aliased
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo syscall=test comm=hello hi"}, &AuditMessage{Type: uint16(1309), Data: "argc=3 a0=\"hello\" a1=\"foo\" a2=\""}}}, &StatsdConfig{kind: "statsd", tokens: map[uint16]map[string]string{uint16(1309): {"args": "did"}}}, "goaudit.syscall.test.count.did_foo:1|c"},
		// test args token in dogstastd metric, unaliased
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo syscall=test comm=hello success=yes exit=0 hi"}, &AuditMessage{Type: uint16(1309), Data: "argc=3 a0=\"hello\" a1=\"foo\" a2=\""}}}, &StatsdConfig{kind: "dogstatsd", tokens: map[uint16]map[string]string{uint16(1309): {"args": ""}}}, "goaudit.syscall.test.count:1|c|#arg:foo"},
		// test args token in dogstastd metric, aliased
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo syscall=test comm=hello success=yes exit=0 hi"}, &AuditMessage{Type: uint16(1309), Data: "argc=3 a0=\"hello\" a1=\"foo\" a2=\""}}}, &StatsdConfig{kind: "dogstatsd", tokens: map[uint16]map[string]string{uint16(1309): {"args": "did"}}}, "goaudit.syscall.test.count:1|c|#did:foo"},
		// test args token in dogststd events, unaliased
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo syscall=test comm=hello key=event hi"}, &AuditMessage{Type: uint16(1309), Data: "argc=3 a0=\"hello\" a1=\"foo\" a2=\""}}}, &StatsdConfig{kind: "dogstatsd", tokens: map[uint16]map[string]string{uint16(1309): {"args": ""}}}, "_e{29,86}:Go-Audit Syscall test ocurred|  hi there tag=waldo syscall=test comm=hello key=event hi  argc=3 a0=hello a1=foo a2= |s:goaudit|#arg:foo"},
		// test args token in dogstatsd events, aliased
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo syscall=test comm=hello key=event hi"}, &AuditMessage{Type: uint16(1309), Data: "argc=3 a0=\"hello\" a1=\"foo\" a2=\""}}}, &StatsdConfig{kind: "dogstatsd", tokens: map[uint16]map[string]string{uint16(1309): {"args": "did"}}}, "_e{29,86}:Go-Audit Syscall test ocurred|  hi there tag=waldo syscall=test comm=hello key=event hi  argc=3 a0=hello a1=foo a2= |s:goaudit|#did:foo"},
		// test name token in statsd, unaliased
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo syscall=test comm=hello hi"}, &AuditMessage{Type: uint16(1302), Data: "item=0 name=\"/foo/bar\" inode=23021 dev=08:01 mode=0100755 nametype=NORMAL"}}}, &StatsdConfig{kind: "statsd", tokens: map[uint16]map[string]string{uint16(1302): {"name": ""}}}, "goaudit.syscall.test.count.name_/foo/bar:1|c"},
		// test name token in statsd, aliased
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo syscall=test comm=hello hi"}, &AuditMessage{Type: uint16(1302), Data: "item=0 name=\"/foo/bar\" inode=23021 dev=08:01 mode=0100755 nametype=NORMAL"}}}, &StatsdConfig{kind: "statsd", tokens: map[uint16]map[string]string{uint16(1302): {"name": "path"}}}, "goaudit.syscall.test.count.path_/foo/bar:1|c"},
		// dogstatsd metrics do not get name tag applied
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo syscall=test comm=hello success=yes exit=0 hi"}, &AuditMessage{Type: uint16(1302), Data: "item=0 name=\"/foo/bar\" inode=23021 dev=08:01 mode=0100755 nametype=NORMAL"}}}, &StatsdConfig{kind: "dogstatsd", tokens: map[uint16]map[string]string{uint16(1302): {"name": ""}}}, "goaudit.syscall.test.count:1|c"},
		// test name token in dogstatsd events, unaliased
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo syscall=test comm=hello key=event hi"}, &AuditMessage{Type: uint16(1302), Data: "item=0 name=\"/foo/bar\" inode=23021 dev=08:01 mode=0100755 nametype=NORMAL"}}}, &StatsdConfig{kind: "dogstatsd", tokens: map[uint16]map[string]string{uint16(1302): {"name": ""}}}, "_e{29,131}:Go-Audit Syscall test ocurred|  hi there tag=waldo syscall=test comm=hello key=event hi  item=0 name=/foo/bar inode=23021 dev=08:01 mode=0100755 nametype=NORMAL |s:goaudit|#name:/foo/bar"},
		// test name token in dogstastd event, aliased
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo syscall=test comm=hello key=event hi"}, &AuditMessage{Type: uint16(1302), Data: "item=0 name=\"/foo/bar\" inode=23021 dev=08:01 mode=0100755 nametype=NORMAL"}}}, &StatsdConfig{kind: "dogstatsd", tokens: map[uint16]map[string]string{uint16(1302): {"name": "path"}}}, "_e{29,131}:Go-Audit Syscall test ocurred|  hi there tag=waldo syscall=test comm=hello key=event hi  item=0 name=/foo/bar inode=23021 dev=08:01 mode=0100755 nametype=NORMAL |s:goaudit|#path:/foo/bar"},
		// test stastd with multiple tags
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo comm=foo syscall=test hi"}}}, &StatsdConfig{kind: "statsd", tokens: map[uint16]map[string]string{uint16(1300): {"tag": "name", "comm": ""}}}, "goaudit.syscall.test.count.comm_foo.name_waldo:1|c"},
		// test dogstatsd with multiple tags
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo syscall=test success=yes exit=0 hi"}}}, &StatsdConfig{kind: "dogstatsd", tokens: map[uint16]map[string]string{uint16(1300): {"success": "worked", "tag": "nope", "exit": ""}}}, "goaudit.syscall.test.count:1|c|#exit:0,worked:yes"},
		// test dogstatsd events with multiple tags
		{&AuditMessageGroup{Msgs: []*AuditMessage{&AuditMessage{Type: uint16(1300), Data: " hi there tag=waldo syscall=test comm=foo key=event,bar hi"}}}, &StatsdConfig{kind: "dogstatsd", tokens: map[uint16]map[string]string{uint16(1300): {"key": "rule_group", "tag": "whereis", "comm": ""}}}, "_e{58,60}:Go-Audit Syscall test ocurred and matched on Key Group bar|  hi there tag=waldo syscall=test comm=foo key=event,bar hi |s:goaudit|#comm:foo,rule_group:bar,whereis:waldo"},
	}
	// todo
	c := 0
	for _, ta := range ts {
		c++
		if r := formatDatagram(ta.msg, ta.sc); r != ta.result {
			t.Error(
				"For test", c,
				"expected", ta.result,
				"got", r,
			)
		}
	}
}
