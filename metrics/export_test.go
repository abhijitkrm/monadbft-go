package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrometheusHandler(t *testing.T) {
	var m Metrics
	m.ConsensusEvents.VoteReceived.Add(3)
	m.ConsensusEvents.CreatedQC.Inc()
	m.BlocksyncEvents.SelfPayloadRequestsInFlight.Set(7)
	m.NodeState.SelfStakeBps.Set(2500)

	rr := httptest.NewRecorder()
	PrometheusHandler(&m).ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()

	for _, want := range []string{
		"# TYPE monadbft_consensus_events_vote_received counter",
		"monadbft_consensus_events_vote_received 3\n",
		"monadbft_consensus_events_created_qc 1\n",
		"# TYPE monadbft_node_state_self_stake_bps gauge",
		"monadbft_node_state_self_stake_bps 2500\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in exposition", want)
		}
	}
}
