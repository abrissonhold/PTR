package database

import (
	"testing"
)

func TestNilDBClientSafety(t *testing.T) {
	var client *DBClient = nil

	err := client.RecordTraffic("192.168.1.1", 10, false)
	if err != nil {
		t.Errorf("expected no error on nil client, got %v", err)
	}

	eventID, err := client.RecordBlockEvent("192.168.1.1", 50, 15)
	if err != nil || eventID != 0 {
		t.Errorf("expected eventID 0 and no error on nil client, got %d, %v", eventID, err)
	}

	err = client.RecordUnblockEvent("192.168.1.1", 1)
	if err != nil {
		t.Errorf("expected no error on nil client, got %v", err)
	}

	err = client.Close()
	if err != nil {
		t.Errorf("expected no error on closing nil client, got %v", err)
	}
}
